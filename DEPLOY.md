# Deploy SecureComm server on Railway (free / $1 plan)

This is ONE file (server.py): blockchain auth + token-gated WebSocket relay + admin dashboard.
It fits Railway's small plan (0.5 GB RAM). The only real change for "free" is adding a Volume so
your SQLite users + blockchain survive redeploys.

## 1. Push these files to a GitHub repo
server.py  requirements.txt  Procfile  railway.json  Dockerfile  runtime.txt  .gitignore  test_server.py

## 2. Create the service
- Railway → New Project → Deploy from GitHub repo → pick this repo.
- Railway builds from the Dockerfile and runs `python server.py`. It injects $PORT automatically.

## 3. Add a Volume (so users/chain persist — the free plan includes 0.5 GB)
- Service → Variables/Settings → add a **Volume**, mount path: `/data`
- Then set these variables so the DB + chain live on the volume:
  - `DB_PATH=/data/users.db`
  - `CHAIN_PATH=/data/chain.json`
  (Without a volume, both reset on every redeploy.)

## 4. Set environment variables
- `AUTH_SECRET`  = a long random string (REQUIRED)        e.g. run: openssl rand -hex 32
- `DB_PATH`      = /data/users.db
- `CHAIN_PATH`   = /data/chain.json
- optional: `CORS_ORIGIN=https://your-web-domain`, `TOKEN_TTL=3600`, `POW_DIFFICULTY=3`,
  `ADMIN_KEY=<key>` (then /delete-user requires header X-Admin-Key)

## 5. IMPORTANT — run as a SINGLE process (1 instance / 1 worker)
This server keeps state in memory (online `peers`, the in-RAM blockchain). Multiple workers/replicas
would each have their OWN copy, so peers in different workers can't see each other and the chain
would fork. So:
- Keep the start command `python server.py` (single process). DO NOT scale replicas > 1.
- If you prefer gunicorn, use exactly ONE worker: `gunicorn -w 1 -k gevent -b 0.0.0.0:$PORT server:app`
  (needs gevent — already in requirements.txt).

## 6. Verify
- Open `https://<your-app>.up.railway.app/health`  -> {"status":"ok",...}
- Open `https://<your-app>.up.railway.app/`         -> the live dashboard (add/delete users)

## 7. Point the clients
- Web client + mobile app "Server" field:  `wss://<your-app>.up.railway.app/ws`
- Login (accounts are created on the dashboard). The relay only admits users that exist on the server.

## Free-tier notes (2026)
- Trial = $5 credits / 30 days (credit card required), then the Free plan ($1/month) keeps a small
  service alive: ~1 vCPU, 0.5 GB RAM, 0.5 GB volume, 1 project. When trial credits run out the
  service pauses (data is preserved) until you upgrade.
- 0.5 GB RAM is enough here. Keep POW_DIFFICULTY at 3 (mining a block is milliseconds).
- 0.5 GB volume is plenty for users.db + chain.json.

## Local run (Windows cmd)
    set AUTH_SECRET=dev-secret
    set PORT=8080
    python server.py
