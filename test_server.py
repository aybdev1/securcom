"""Security tests for the single-file server. Run: pytest -v test_server.py"""
import importlib, os, pytest

@pytest.fixture
def srv(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "test-secret")
    monkeypatch.setenv("CHAIN_PATH", str(tmp_path / "c.json"))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "u.db"))
    monkeypatch.setenv("POW_DIFFICULTY", "2")
    import server; importlib.reload(server)
    return server

def test_token_roundtrip(srv):
    assert srv.verify_token(srv.make_token("a")) == "a"
def test_token_expired(srv):
    assert srv.verify_token(srv.make_token("a", ttl=-1)) is None
def test_token_forged(srv):
    t = srv.make_token("a"); p, s = t.split("."); assert srv.verify_token(p[:-1] + ("X" if p[-1] != "X" else "Y") + "." + s) is None
def test_password_hash(srv):
    salt, h = srv.hash_password("password123"); assert "password123" not in salt + h
    assert srv.verify_password("password123", salt, h) and not srv.verify_password("x", salt, h)
def test_chain_tamper(srv):
    bc = srv.Blockchain(difficulty=2, path=None); bc.add_block({"type": "register", "username": "u"})
    assert bc.is_valid(); bc.chain[1].data["username"] = "evil"; assert bc.is_valid() is False
def test_validation(srv):
    assert srv.valid_username("good_1") and not srv.valid_username("a") and not srv.valid_username("bad space")
    assert srv.valid_password("longenough") and not srv.valid_password("short")
def test_rate_limit(srv):
    rl = srv.RateLimiter(max_hits=2, window=60); assert rl.allow("k") and rl.allow("k") and rl.allow("k") is False

@pytest.fixture
def client(srv): return srv.app.test_client()

def test_flow(client):
    assert client.post("/register", json={"username": "zoe", "password": "password123"}).status_code == 201
    assert client.post("/register", json={"username": "zoe", "password": "password123"}).status_code == 409  # dup
    assert client.post("/login", json={"username": "zoe", "password": "password123"}).status_code == 200
    assert client.post("/login", json={"username": "zoe", "password": "WRONG"}).status_code == 401
    body = client.get("/chain").get_json(); assert body["valid"] and "password123" not in str(body)

# ---- SQLite store + key transparency ----
def test_sqlite_register_and_verify(client, srv):
    r = client.post("/register", json={"username": "alice.gov", "password": "password123", "identity": "BASE64PUBKEY=="})
    assert r.status_code == 201
    fp = r.get_json()["identity_fp"]; assert fp
    v = client.get("/verify?username=alice.gov").get_json()
    assert v["exists"] is True and v["identity"] == "BASE64PUBKEY==" and v["identity_fp"] == fp
    assert client.get("/verify?username=ghost").get_json()["exists"] is False

def test_identity_on_chain_matches(client):
    client.post("/register", json={"username": "bob.gov", "password": "password123", "identity": "BOBKEY=="})
    onchain = client.get("/identity/bob.gov").get_json()
    verify = client.get("/verify?username=bob.gov").get_json()
    assert onchain["on_chain"] is True
    assert onchain["identity_fp"] == verify["identity_fp"]   # DB fp == immutable chain fp

def test_db_persists_across_reload(tmp_path, monkeypatch):
    import importlib
    monkeypatch.setenv("AUTH_SECRET", "test-secret")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "u.db"))
    monkeypatch.setenv("CHAIN_PATH", str(tmp_path / "c.json"))
    monkeypatch.setenv("POW_DIFFICULTY", "2")
    import server; importlib.reload(server)
    server.app.test_client().post("/register", json={"username": "persist", "password": "password123"})
    importlib.reload(server)   # simulate restart — DB file remains
    assert server.db.exists("persist")

def test_login_uses_db(client):
    client.post("/register", json={"username": "dbuser", "password": "password123"})
    assert client.post("/login", json={"username": "dbuser", "password": "password123"}).status_code == 200
    assert client.post("/login", json={"username": "dbuser", "password": "WRONGPASS"}).status_code == 401

# ---- delete user (revocation) ----
def test_delete_user_blocks_access(client, srv):
    client.post("/register", json={"username": "revokeme", "password": "password123"})
    assert srv.db.exists("revokeme") is True
    r = client.post("/delete-user", json={"username": "revokeme"})
    assert r.status_code == 200 and r.get_json()["deleted"] is True
    assert srv.db.exists("revokeme") is False                     # gone from DB
    # relay gate uses db.exists(sub) -> a deleted user can no longer connect
    tok = srv.make_token("revokeme")
    assert srv.verify_token(tok) == "revokeme"                    # token still signed...
    assert srv.db.exists("revokeme") is False                     # ...but user doesn't exist -> rejected
    assert client.post("/delete-user", json={"username": "ghost"}).status_code == 404

def test_login_binds_identity(client, srv):
    client.post("/register", json={"username": "binduser", "password": "password123"})  # no identity
    assert srv.db.get("binduser")["identity"] in (None, "")
    client.post("/login", json={"username": "binduser", "password": "password123", "identity": "DEVICEKEY=="})
    assert srv.db.get("binduser")["identity"] == "DEVICEKEY=="     # bound on first login
