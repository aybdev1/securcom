"""SecureComm — single-file server: blockchain auth + token-gated signaling relay.

ONE process, ONE port. Users register/login (HTTP) to get a token; the WebSocket relay
(/ws) refuses any connection without a valid token. Everything below — token logic, password
hashing, the tamper-evident hash-chain ('blockchain'), the auth API, and the relay — lives here.

Run:    pip install flask flask-sock
        AUTH_SECRET="a-long-random-secret" PORT=8080 python server.py
Deploy: one Railway service. Start command: python server.py  (Railway sets PORT).
        For scale:  gunicorn -k gevent -b 0.0.0.0:$PORT server:app

HONEST SCOPE: the 'blockchain' is a single-node, proof-of-work, tamper-evident hash chain
(an append-only audit ledger) — not a distributed consensus network.
"""
import os, json, time, hashlib, hmac, base64, re, threading, sqlite3
from flask import Flask, request, jsonify
from flask_sock import Sock

# ----------------------------------------------------------------------------- config
AUTH_SECRET    = os.environ.get("AUTH_SECRET", "change-me-please-shared-secret")
TOKEN_TTL      = int(os.environ.get("TOKEN_TTL", "2592000"))  # 30 days. (Was 3600=1h, which dropped clients off the relay after an hour because the WS reconnect kept presenting an expired token.)
CHAIN_PATH     = os.environ.get("CHAIN_PATH", "chain.json")
DB_PATH        = os.environ.get("DB_PATH", "users.db")
POW_DIFFICULTY = int(os.environ.get("POW_DIFFICULTY", "3"))
REQUIRE_AUTH   = os.environ.get("REQUIRE_AUTH", "1") == "1"
REGISTRATION_OPEN = os.environ.get("REGISTRATION_OPEN", "1") == "1"  # set 0 to disable public sign-up
ADMIN_KEY      = os.environ.get("ADMIN_KEY", "") # if set, /delete-user requires header X-Admin-Key
PBKDF2_ITERS   = 200_000

# ----------------------------------------------------------------------------- tokens (HMAC)
def _b64(b):   return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def make_token(username, ttl=TOKEN_TTL):
    payload = {"sub": username, "exp": int(time.time()) + int(ttl), "iat": int(time.time())}
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(AUTH_SECRET.encode(), p.encode(), hashlib.sha256).digest()
    return p + "." + _b64(sig)

def verify_token(token):
    try:
        p, s = token.split(".", 1)
        expected = hmac.new(AUTH_SECRET.encode(), p.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_unb64(s), expected):       # constant-time
            return None
        payload = json.loads(_unb64(p))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload.get("sub")
    except Exception:
        return None

# ----------------------------------------------------------------------------- security helpers
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    return salt.hex(), dk.hex()

def verify_password(password, salt_hex, hash_hex):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ITERS)
    return hmac.compare_digest(dk.hex(), hash_hex)             # constant-time

def valid_username(u): return bool(u) and bool(_USERNAME_RE.match(u))
def valid_password(p): return isinstance(p, str) and 8 <= len(p) <= 128

class RateLimiter:
    def __init__(self, max_hits=10, window=60):
        self.max_hits, self.window, self._hits, self._lock = max_hits, window, {}, threading.Lock()
    def allow(self, key):
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(hits) >= self.max_hits:
                self._hits[key] = hits; return False
            hits.append(now); self._hits[key] = hits; return True

# ----------------------------------------------------------------------------- blockchain
class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index, self.timestamp, self.data = index, timestamp, data
        self.previous_hash, self.nonce = previous_hash, nonce
    def compute_hash(self):
        return hashlib.sha256(json.dumps({
            "index": self.index, "timestamp": self.timestamp, "data": self.data,
            "previous_hash": self.previous_hash, "nonce": self.nonce}, sort_keys=True).encode()).hexdigest()
    def to_dict(self):
        d = {"index": self.index, "timestamp": self.timestamp, "data": self.data,
             "previous_hash": self.previous_hash, "nonce": self.nonce}
        d["hash"] = self.compute_hash(); return d

class Blockchain:
    def __init__(self, difficulty=POW_DIFFICULTY, path=CHAIN_PATH):
        self.difficulty, self.path, self.chain = difficulty, path, []
        if path and os.path.exists(path): self._load()
        else: self._genesis()
    def _genesis(self):
        g = Block(0, time.time(), {"type": "genesis"}, "0"); self.proof_of_work(g)
        self.chain.append(g); self._save()
    @property
    def last(self): return self.chain[-1]
    def proof_of_work(self, block):
        block.nonce = 0; target = "0" * self.difficulty
        while not block.compute_hash().startswith(target): block.nonce += 1
        return block.compute_hash()
    def add_block(self, data):
        b = Block(len(self.chain), time.time(), data, self.last.compute_hash())
        self.proof_of_work(b); self.chain.append(b); self._save(); return b
    def is_valid(self):
        target = "0" * self.difficulty
        for i in range(1, len(self.chain)):
            cur, prev = self.chain[i], self.chain[i-1]
            if cur.previous_hash != prev.compute_hash(): return False
            if not cur.compute_hash().startswith(target): return False
        return True
    def find_user(self, username):
        found = None
        for b in self.chain:
            if b.data.get("type") == "register" and b.data.get("username") == username:
                found = b.data
        return found
    def _save(self):
        if self.path:
            with open(self.path, "w") as f: json.dump([b.to_dict() for b in self.chain], f)
    def _load(self):
        with open(self.path) as f: raw = json.load(f)
        self.chain = [Block(b["index"], b["timestamp"], b["data"], b["previous_hash"], b["nonce"]) for b in raw]
    def reset(self):
        """Wipe every block and start a brand-new chain from a fresh genesis block."""
        self.chain = []; self._genesis(); return len(self.chain)

# ----------------------------------------------------------------------------- dashboard
DASHBOARD_HTML = """<!DOCTYPE html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>SecureComm — live</title>
<style>
:root{--bg:#0b0f14;--panel:#121922;--panel2:#0f141c;--line:rgba(255,255,255,.06);
--text:#e8edf3;--muted:#8fa3b5;--accent:#25d366;--accent2:#34b7f1;--danger:#ff4d4d;--amber:#ffb300}
*{box-sizing:border-box;margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial}
body{background:radial-gradient(1200px 600px at 80% -10%,rgba(37,211,102,.10),transparent),
radial-gradient(900px 500px at -10% 10%,rgba(52,183,241,.08),transparent),var(--bg);color:var(--text);min-height:100vh;padding:28px}
.wrap{max-width:1100px;margin:0 auto}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));
display:grid;place-items:center;font-size:22px;box-shadow:0 8px 24px rgba(37,211,102,.35)}
h1{font-size:20px;font-weight:700}.sub{color:var(--muted);font-size:12px}
.live{display:flex;align-items:center;gap:8px;background:var(--panel);padding:8px 14px;border-radius:999px;border:1px solid var(--line);font-size:13px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 0 rgba(37,211,102,.7);animation:pulse 1.8s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(37,211,102,.6)}70%{box-shadow:0 0 0 10px rgba(37,211,102,0)}100%{box-shadow:0 0 0 0 rgba(37,211,102,0)}}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:22px}
@media(max-width:760px){.cards{grid-template-columns:repeat(2,1fr)}}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:16px;padding:18px;position:relative;overflow:hidden}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:30px;font-weight:800;margin-top:8px}
.card .v small{font-size:13px;font-weight:600;color:var(--muted)}
.ok{color:var(--accent)}.bad{color:var(--danger)}
.grid{display:grid;grid-template-columns:1.3fr 1fr;gap:16px}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
.panel{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:16px;padding:18px}
.panel h2{font-size:14px;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.count{margin-left:auto;background:rgba(37,211,102,.14);color:var(--accent);padding:2px 10px;border-radius:999px;font-size:12px}
.user{display:flex;align-items:center;gap:12px;padding:11px 6px;border-bottom:1px solid var(--line);animation:fade .4s ease}
.user:last-child{border-bottom:none}
.av{width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#2b3440,#1a2230);display:grid;place-items:center;font-weight:700;position:relative;color:var(--accent)}
.av i{position:absolute;right:-1px;bottom:-1px;width:11px;height:11px;border-radius:50%;background:var(--accent);border:2px solid var(--panel)}
.uid{font-weight:600}.umeta{color:var(--muted);font-size:12px}
.empty{color:var(--muted);font-size:13px;text-align:center;padding:24px 0}
input.f{width:100%;padding:10px 12px;margin:6px 0;border-radius:10px;border:1px solid var(--line);background:#0d131b;color:var(--text);font-size:13px}
button.b{width:100%;padding:11px;border:none;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#04210f;font-weight:700;cursor:pointer;margin-top:4px}
button.b:active{transform:translateY(1px)}.msg{font-size:12px;margin-top:8px;min-height:16px}
button.del{background:rgba(255,77,77,.14);color:var(--danger);border:none;border-radius:8px;width:30px;height:30px;cursor:pointer;font-size:13px}
button.del:hover{background:rgba(255,77,77,.28)}
.act{display:flex;align-items:center;gap:10px;padding:9px 4px;border-bottom:1px solid var(--line);font-size:13px}
.act:last-child{border-bottom:none}
.tag{font-size:11px;padding:2px 8px;border-radius:6px;font-weight:700;text-transform:uppercase}
.tag.reg{background:rgba(52,183,241,.16);color:var(--accent2)}.tag.log{background:rgba(37,211,102,.16);color:var(--accent)}
.ago{margin-left:auto;color:var(--muted);font-size:12px}
footer{color:var(--muted);font-size:11px;text-align:center;margin-top:22px}
.users-scroll{
  max-height: 380px;
  overflow-y: auto;
  padding-right: 8px;

  scrollbar-width: thin;
  scrollbar-color: var(--accent) transparent;
}
/* Chrome / Edge / Safari */
.users-scroll::-webkit-scrollbar{
  width: 7px;
}
.users-scroll::-webkit-scrollbar-thumb{
  background: linear-gradient(var(--accent), var(--accent2));
  border-radius: 10px;
}
.users-scroll::-webkit-scrollbar-track{
  background: transparent;
}

</style></head><body><div class=wrap>
<header><div class=brand><div class=logo>&#128274;</div><div><h1>SecureComm</h1>
<div class=sub>blockchain auth + signaling relay &middot; single service</div></div></div>
<div class=live><span class=dot></span><span id=livetxt>live</span></div></header>
<div class=cards>
<div class=card><div class=k>Online now</div><div class="v ok" id=c_online>0</div></div>
<div class=card><div class=k>Registered users</div><div class=v id=c_users>0</div></div>
<div class=card><div class=k>Chain blocks</div><div class=v id=c_blocks>0</div></div>
<div class=card><div class=k>Chain integrity</div><div class=v id=c_valid>&mdash;</div></div>
</div>
<div class=grid>
<div class=panel><h2>&#128081; Connected now <span class=count id=onlinecount>0</span></h2><div id=online></div></div>
<div class=panel><h2>&#9889; Recent activity</h2>  <div class="users-scroll"><div id=recent></div></div></div>
</div>
<div class=grid style="margin-top:16px">
<div class=panel><h2>&#10133; Add user</h2>
<input class=f id=nu placeholder="username (3-32: letters, digits, . _ -)">
<input class=f id=np type=password placeholder="password (8+ chars)">
<button class=b onclick=addUser()>Add user</button>
<div class=msg id=addmsg></div></div>
<div class="panel">
  <h2>
    &#128101; Registered users
    <span class="count" id="usercount">0</span>
  </h2>

  <div class="users-scroll">
    <div id="users"></div>
  </div>
</div>
</div>

<div class=panel><h2>&#9888;&#65039; Danger zone</h2>
<p style="font-size:13px;color:var(--muted);margin:-4px 0 12px">Irreversible. If the server has an ADMIN_KEY set, you'll be asked for it once.</p>
<button class=b style="background:#92400e" onclick=resetChain()>Reset blockchain &middot; keep users</button>
<div style="height:8px"></div>
<button class=b style="background:#991b1b" onclick=resetAll()>Reset EVERYTHING &middot; delete all users + chain</button>
<div class=msg id=dangermsg></div></div>
</div>
<footer>auto-refreshing every 2s &middot; uptime <span id=uptime>0s</span> &middot; this page shows usernames only (never passwords)</footer>
</div>
<script>
function ago(s){if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';if(s<86400)return Math.floor(s/3600)+'h';return Math.floor(s/86400)+'d';}
function esc(t){return (t||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
async function tick(){
 try{
  const r=await fetch('/stats',{cache:'no-store'});const d=await r.json();
  c_online.textContent=d.online_count;onlinecount.textContent=d.online_count;
  c_users.textContent=d.users;c_blocks.textContent=d.blocks;
  c_valid.innerHTML=d.valid?'<span class=ok>&#10003; valid</span>':'<span class=bad>&#10007; broken</span>';
  uptime.textContent=ago(d.uptime);livetxt.textContent='live';
  online.innerHTML = d.online.length ? d.online.map(u=>`<div class=user><div class=av>${esc(u.id[0]||'?').toUpperCase()}<i></i></div>
    <div><div class=uid>${esc(u.id)}</div><div class=umeta>connected ${ago(u.since)} ago</div></div></div>`).join('')
    : '<div class=empty>No users connected right now.</div>';
  recent.innerHTML = d.recent.length ? d.recent.map(a=>`<div class=act><span class="tag ${a.type==='register'?'reg':'log'}">${a.type}</span>
    <b>${esc(a.username)}</b><span class=ago>${ago(a.ago)} ago</span></div>`).join('')
    : '<div class=empty>No activity yet.</div>';
 }catch(e){livetxt.textContent='reconnecting…';}
}
async function loadUsers(){
 try{const r=await fetch('/users',{cache:'no-store'});const d=await r.json();
  usercount.textContent=d.count;
  users.innerHTML = d.users.length ? d.users.map(u=>`<div class=user><div class=av>${esc(u[0]||'?').toUpperCase()}</div>
   <div style="flex:1"><div class=uid>${esc(u)}</div><div class=umeta>registered</div></div>
   <button class=del title="Delete user" onclick="deleteUser('${esc(u)}')">&#10005;</button></div>`).join('')
   : '<div class=empty>No users yet. Add one on the left.</div>';
 }catch(e){}
}
async function deleteUser(u){
 if(!confirm('Delete user "'+u+'"? They will be disconnected and blocked from the server.')) return;
 try{
  const r=await fetch('/delete-user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})});
  const j=await r.json().catch(()=>({}));
  const m=document.getElementById('addmsg');
  if(r.ok&&j.deleted){m.style.color='var(--accent)';m.textContent='✓ Deleted '+u;loadUsers();}
  else{m.style.color='var(--danger)';m.textContent='✗ '+(j.error||('HTTP '+r.status));}
 }catch(e){}
}
function _adminHeaders(){ const k=localStorage.getItem('sc_admin_key')||''; const h={'Content-Type':'application/json'}; if(k) h['X-Admin-Key']=k; return h; }
async function _adminPost(url, confirmMsg){
 if(!confirm(confirmMsg)) return;
 let key=localStorage.getItem('sc_admin_key');
 if(key===null){ key=prompt('Admin key (leave blank if none is configured on the server):',''); if(key===null) return; localStorage.setItem('sc_admin_key', key); }
 const m=document.getElementById('dangermsg'); m.style.color='var(--muted)'; m.textContent='Working…';
 try{
  const r=await fetch(url,{method:'POST',headers:_adminHeaders()}); const j=await r.json().catch(()=>({}));
  if(r.ok){ m.style.color='var(--accent)'; m.textContent='\u2713 '+(j.action||'done')+': blocks='+j.blocks+(j.users_deleted!=null?(', users deleted='+j.users_deleted):''); loadUsers(); }
  else{ m.style.color='var(--danger)'; m.textContent='\u2717 '+(j.error||('HTTP '+r.status)); if(r.status===403) localStorage.removeItem('sc_admin_key'); }
 }catch(e){ m.style.color='var(--danger)'; m.textContent='\u2717 '+e.message; }
}
function resetChain(){ _adminPost('/admin/reset-chain','Delete the ENTIRE blockchain and start a fresh genesis block? Users are kept.'); }
function resetAll(){ _adminPost('/admin/reset-all','DELETE EVERYTHING \u2014 all users, the whole blockchain, all sessions. This cannot be undone. Continue?'); }
async function addUser(){
 const u=document.getElementById('nu').value.trim(), p=document.getElementById('np').value;
 const m=document.getElementById('addmsg');
 if(!u||!p){m.style.color='var(--amber)';m.textContent='Enter username + password.';return;}
 m.style.color='var(--muted)';m.textContent='Adding…';
 try{
  const r=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
  const j=await r.json().catch(()=>({}));
  if(r.status===201){m.style.color='var(--accent)';m.textContent='✓ Added '+u;document.getElementById('nu').value='';document.getElementById('np').value='';loadUsers();}
  else{m.style.color='var(--danger)';m.textContent='✗ '+(j.error||('HTTP '+r.status));}
 }catch(e){m.style.color='var(--danger)';m.textContent='✗ '+e.message;}
}
tick();loadUsers();setInterval(()=>{tick();loadUsers();},2000);
</script></body></html>"""

# ----------------------------------------------------------------------------- app
app = Flask(__name__)
app.config['SOCK_SERVER_OPTIONS'] = {'max_message_size': 24 * 1024 * 1024}  # allow large encrypted file frames
sock = Sock(app)
class UserDB:
    """SQLite user store for fast verification (easy to deploy/persist). The blockchain remains
    the tamper-evident audit + key-transparency ledger; this table is the queryable index."""
    def __init__(self, path):
        self.path, self._lock = path, threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY, salt TEXT, pwd_hash TEXT, identity TEXT, created_at REAL)""")
        self.conn.commit()
    def get(self, username):
        with self._lock:
            r = self.conn.execute(
                "SELECT username,salt,pwd_hash,identity,created_at FROM users WHERE username=?",
                (username,)).fetchone()
        return None if not r else {"username": r[0], "salt": r[1], "pwd_hash": r[2],
                                   "identity": r[3], "created_at": r[4]}
    def exists(self, username): return self.get(username) is not None
    def add(self, username, salt, pwd_hash, identity):
        with self._lock:
            self.conn.execute(
                "INSERT INTO users(username,salt,pwd_hash,identity,created_at) VALUES(?,?,?,?,?)",
                (username, salt, pwd_hash, identity, time.time()))
            self.conn.commit()
    def count(self):
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    def usernames(self):
        with self._lock:
            return [r[0] for r in self.conn.execute(
                "SELECT username FROM users ORDER BY created_at DESC").fetchall()]
    def delete(self, username):
        with self._lock:
            cur = self.conn.execute("DELETE FROM users WHERE username=?", (username,))
            self.conn.commit()
            return cur.rowcount > 0
    def update_identity(self, username, identity):
        with self._lock:
            self.conn.execute("UPDATE users SET identity=? WHERE username=?", (identity, username))
            self.conn.commit()
    def delete_all(self):
        with self._lock:
            n = self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            self.conn.execute("DELETE FROM users"); self.conn.commit()
            return n

def fp_of(identity): return hashlib.sha256((identity or "").encode()).hexdigest()[:32] if identity else ""

chain = Blockchain()
db = UserDB(DB_PATH)
reg_limiter = RateLimiter(max_hits=5, window=60)
login_limiter = RateLimiter(max_hits=10, window=60)
peers = {}
peer_since = {}
START_TS = time.time()

# ---- Offline store-and-forward queue ----
# When a recipient is briefly offline, queue their messages and flush on reconnect, so a
# transient disconnect no longer means "undeliverable". Bounded by count + age to limit memory.
import collections
QUEUE_MAX_PER_USER = int(os.environ.get("QUEUE_MAX_PER_USER", "500"))
QUEUE_TTL = int(os.environ.get("QUEUE_TTL", str(7 * 24 * 3600)))  # seconds
pending = collections.defaultdict(collections.deque)  # id -> deque[(ts, msg_dict)]

def _enqueue(to, msg):
    q = pending[to]
    now = time.time()
    # prune expired
    while q and (now - q[0][0]) > QUEUE_TTL:
        q.popleft()
    q.append((now, msg))
    while len(q) > QUEUE_MAX_PER_USER:
        q.popleft()
    return len(q)

def _flush(to, ws):
    q = pending.get(to)
    if not q:
        return 0
    now = time.time()
    sent = 0
    while q:
        ts, msg = q.popleft()
        if (now - ts) > QUEUE_TTL:
            continue
        try:
            ws.send(json.dumps(msg)); sent += 1
        except Exception:
            q.appendleft((ts, msg)); break
    if not q:
        pending.pop(to, None)
    return sent

def _ip(): return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()

CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")  # set to your web origin in production

@app.before_request
def _preflight():
    if request.method == "OPTIONS":
        return ("", 204)

@app.after_request
def _hdr(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Access-Control-Allow-Origin"] = CORS_ORIGIN
    r.headers["Access-Control-Allow-Headers"] = "Content-Type"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return r

@app.get("/")
def home():
    return DASHBOARD_HTML

@app.get("/stats")
def stats():
    now = time.time()
    online = [{"id": pid, "since": int(now - peer_since.get(pid, now))} for pid in list(peers.keys())]
    users = db.count()
    recent = []
    for b in reversed(chain.chain):
        t = b.data.get("type")
        if t in ("register", "login"):
            recent.append({"type": t, "username": b.data.get("username"), "ago": int(now - b.timestamp)})
        if len(recent) >= 12:
            break
    return jsonify(online=online, online_count=len(online), users=users, recent=recent,
                   blocks=len(chain.chain), valid=chain.is_valid(), uptime=int(now - START_TS))

@app.get("/health")
def health():
    return jsonify(status="ok", peers=len(peers), chain_valid=chain.is_valid(),
                   blocks=len(chain.chain), auth_required=REQUIRE_AUTH, registration_open=REGISTRATION_OPEN)

@app.post("/register")
def register():
    if not reg_limiter.allow(_ip()): return jsonify(error="rate limited"), 429
    # Public registration can be turned off (REGISTRATION_OPEN=0). An admin presenting the
    # X-Admin-Key may still create accounts even when public sign-up is disabled.
    admin_ok = bool(ADMIN_KEY) and request.headers.get("X-Admin-Key", "") == ADMIN_KEY
    if not REGISTRATION_OPEN and not admin_ok:
        return jsonify(error="registration is disabled by the administrator"), 403
    b = request.get_json(silent=True) or {}
    u, p = b.get("username", ""), b.get("password", "")
    if not valid_username(u): return jsonify(error="invalid username (3-32: letters, digits, . _ -)"), 400
    if not valid_password(p): return jsonify(error="invalid password (8-128 chars)"), 400
    identity = (b.get("identity") or "")[:512]   # client's identity public key (base64), optional
    if db.exists(u): return jsonify(error="user already exists"), 409
    salt_hex, hash_hex = hash_password(p)
    db.add(u, salt_hex, hash_hex, identity)
    fp = fp_of(identity)
    chain.add_block({"type": "register", "username": u, "identity_fp": fp})  # key transparency
    return jsonify(token=make_token(u), username=u, identity_fp=fp), 201

@app.post("/login")
def login():
    if not login_limiter.allow(_ip()): return jsonify(error="rate limited"), 429
    b = request.get_json(silent=True) or {}
    u, p = b.get("username", ""), b.get("password", "")
    rec = db.get(u) if valid_username(u) else None
    ok = verify_password(p, rec["salt"], rec["pwd_hash"]) if rec else verify_password(p, "00"*16, "ff"*32)
    if not rec or not ok: return jsonify(error="invalid credentials"), 401
    identity = (b.get("identity") or "")[:512]
    if identity and not (rec.get("identity") or ""):       # first-login identity binding
        db.update_identity(u, identity)
        chain.add_block({"type": "bind_identity", "username": u, "identity_fp": fp_of(identity)})
    chain.add_block({"type": "login", "username": u})
    return jsonify(token=make_token(u), username=u, identity_fp=fp_of(identity or rec.get("identity"))), 200

@app.post("/validate")
def validate():
    b = request.get_json(silent=True) or {}
    sub = verify_token(b.get("token", ""))
    return jsonify(valid=bool(sub), sub=sub)

@app.get("/verify")
def verify_user():
    """The mobile app calls this to confirm a user exists in the DB and to fetch their registered
    identity key (key transparency: compare it to the key the peer actually presents)."""
    u = request.args.get("username", "")
    rec = db.get(u) if valid_username(u) else None
    if not rec: return jsonify(exists=False)
    return jsonify(exists=True, username=u, identity=rec["identity"] or "",
                   identity_fp=fp_of(rec["identity"]), created_at=rec["created_at"])

@app.get("/identity/<username>")
def identity_on_chain(username):
    """Returns the identity fingerprint as recorded immutably on the chain (cannot be silently
    altered without breaking chain integrity) — the trust anchor for key transparency."""
    fp = ""
    for blk in chain.chain:
        if blk.data.get("type") == "register" and blk.data.get("username") == username:
            fp = blk.data.get("identity_fp", "")
    return jsonify(username=username, identity_fp=fp, on_chain=bool(fp))

@app.post("/delete-user")
def delete_user():
    if ADMIN_KEY and request.headers.get("X-Admin-Key", "") != ADMIN_KEY:
        return jsonify(error="forbidden"), 403
    b = request.get_json(silent=True) or {}
    u = b.get("username", "")
    if not db.exists(u):
        return jsonify(error="no such user"), 404
    db.delete(u)
    chain.add_block({"type": "delete", "username": u})   # tamper-evident revocation record
    ws = peers.pop(u, None)                               # kick them off the relay immediately
    peer_since.pop(u, None)
    if ws is not None:
        try: ws.close()
        except Exception: pass
    return jsonify(deleted=True, username=u)

def _admin_ok():
    """Admin gate: a matching X-Admin-Key when ADMIN_KEY is set; otherwise only the local
    machine (no key configured = local-only admin, never open to the internet)."""
    if ADMIN_KEY:
        return request.headers.get("X-Admin-Key", "") == ADMIN_KEY
    return _ip() in ("127.0.0.1", "::1", "localhost")

def _kick_all_peers():
    for pid, ws in list(peers.items()):
        try: ws.close()
        except Exception: pass
    peers.clear(); peer_since.clear(); pending.clear()

@app.post("/admin/reset-chain")
def admin_reset_chain():
    """Delete the entire blockchain and re-create a fresh genesis block. Users are kept."""
    if not _admin_ok():
        return jsonify(error="admin key required (set ADMIN_KEY and send X-Admin-Key)"), 403
    blocks = chain.reset()
    return jsonify(status="ok", action="reset-chain", blocks=blocks, chain_valid=chain.is_valid())

@app.post("/admin/reset-all")
def admin_reset_all():
    """Full wipe: reset the chain to genesis, delete ALL users, drop all online peers and
    queued messages. The server returns to a clean, just-installed state."""
    if not _admin_ok():
        return jsonify(error="admin key required (set ADMIN_KEY and send X-Admin-Key)"), 403
    users = db.delete_all()
    blocks = chain.reset()
    _kick_all_peers()
    return jsonify(status="ok", action="reset-all", users_deleted=users,
                   blocks=blocks, chain_valid=chain.is_valid(), peers=len(peers))

@app.get("/users")
def users_list():
    """Registered usernames (no secrets) — lets the dashboard show who exists and lets clients
    confirm a user is registered on the server."""
    return jsonify(users=db.usernames(), count=db.count())

@app.get("/chain")
def get_chain():
    return jsonify(length=len(chain.chain), valid=chain.is_valid(),
                   chain=[b.to_dict() for b in chain.chain])

@sock.route("/ws")
def ws(ws):
    my_id, token = request.args.get("id", ""), request.args.get("token", "")
    if REQUIRE_AUTH:
        sub = verify_token(token)
        # Verify: valid token AND it matches the id AND the user actually exists in the server DB.
        if not sub or (my_id and sub != my_id) or not db.exists(sub):
            try: ws.send(json.dumps({"type": "error", "error": "unauthorized"}))
            finally: return
    if not my_id:
        ws.send(json.dumps({"type": "error", "error": "missing id"})); return
    peers[my_id] = ws
    peer_since[my_id] = time.time()
    ws.send(json.dumps({"type": "registered", "id": my_id}))
    # Deliver anything that arrived while this user was offline.
    flushed = _flush(my_id, ws)
    if flushed:
        try: ws.send(json.dumps({"type": "queued_delivered", "count": flushed}))
        except Exception: pass
    try:
        while True:
            raw = ws.receive()
            if raw is None: break
            try: msg = json.loads(raw)
            except Exception: continue
            mtype = msg.get("type")
            # Heartbeat: keeps the connection alive through proxies; lets clients detect liveness.
            if mtype == "ping":
                try: ws.send(json.dumps({"type": "pong", "t": int(time.time())}))
                except Exception: break
                continue
            to = msg.get("to")
            if to and to in peers:
                msg["from"] = my_id
                try:
                    peers[to].send(json.dumps(msg))
                except Exception:
                    # The target socket died mid-send: queue and let them get it on reconnect.
                    msg["from"] = my_id; depth = _enqueue(to, msg)
                    try: ws.send(json.dumps({"type": "queued", "to": to, "depth": depth}))
                    except Exception: pass
            elif to:
                msg["from"] = my_id
                if mtype == "offer":
                    # Recipient offline: record a MISSED CALL for delivery on reconnect. We do NOT
                    # queue the raw offer (it would ring much later, long after the call is over).
                    _enqueue(to, {"type": "missed_call", "from": my_id, "t": int(time.time()),
                                  "profile": msg.get("profile")})
                    try: ws.send(json.dumps({"type": "undeliverable", "to": to,
                                             "reason": "peer offline — missed call recorded"}))
                    except Exception: pass
                elif mtype in ("answer", "ice", "bye"):
                    # Live call signaling is useless if delivered late — drop it silently.
                    pass
                else:
                    # Chat/key/file message: QUEUE it (store-and-forward) and tell the sender.
                    depth = _enqueue(to, msg)
                    try: ws.send(json.dumps({"type": "queued", "to": to, "depth": depth,
                                             "reason": "peer offline — will deliver when they reconnect"}))
                    except Exception: pass
    finally:
        if peers.get(my_id) is ws: del peers[my_id]
        peer_since.pop(my_id, None)

if __name__ == "__main__":
    # threaded=True so HTTP auth calls and multiple WebSocket relays run concurrently.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), threaded=True)
