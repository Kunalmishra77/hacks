# Deploying scan workers to the VPS

Scan workers run on the VPS as sandboxed Docker containers. They connect *out*
to Supabase (Postgres) and Redis, pull jobs from the queue, re-check the Scope
Authorization Gate, and run their tools. They accept no inbound connections.

There are four workers, one container each, all defined in
`docker-compose.workers.yml`:

- **discovery** — passive subdomains, DNS, HTTP(S) liveness
- **tls** — testssl.sh protocol/cipher/certificate checks
- **web** — security headers, cookie flags, exposed-file probes (no external tools)
- **network** — naabu + fingerprintx port/service scan (Admin-approved scans only)

The API and dashboard can keep running on your PC for now; they share the same
Supabase and Redis. The egress filter in step 4 matters more now: the network
worker makes real TCP connections to many ports, so the firewall is what keeps it
off the VPS's own network and the cloud metadata endpoint.

## 1. Server

- Ubuntu 22.04 or 24.04, 2 vCPU / 4 GB RAM is plenty for one worker.
- Log in as a sudo user (not root) over SSH keys.

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install git ufw iptables-persistent
```

Inbound firewall: workers need nothing inbound, so only SSH is open.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw enable
```

## 2. Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # log out and back in afterwards
docker --version
```

## 3. Code and secrets

```bash
git clone https://github.com/Kunalmishra77/hacks.git aegis && cd aegis
```

Create `workers.env` with **only** what workers need (no JWT secrets, no API
keys). It is gitignored.

```bash
cat > workers.env <<'EOF'
DATABASE_URL="postgresql://postgres.<ref>:<url-encoded-password>@aws-0-<region>.pooler.supabase.com:6543/postgres?pgbouncer=true&connection_limit=3"
REDIS_URL="redis://default:<password>@<host>:<port>"
EOF
chmod 600 workers.env
```

## 4. Egress filter (do this before starting workers)

The worker code already refuses to contact private or reserved addresses. The
host firewall enforces the same thing underneath it, so even a bug or a
hostile DNS answer can't make a worker reach the VPS's own network, other
containers, or the cloud metadata service.

Rules go in Docker's `DOCKER-USER` chain and match traffic leaving the
`aegis-workers` bridge (the name is fixed in `docker-compose.workers.yml`):

```bash
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
           172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4; do
  sudo iptables -I DOCKER-USER -i aegis-workers -d "$net" -j DROP
done
# Replies to connections the worker opened are fine.
sudo iptables -I DOCKER-USER -i aegis-workers -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
sudo netfilter-persistent save
sudo iptables -L DOCKER-USER -n -v   # check
```

If the VPS has IPv6, add the equivalent `ip6tables` rules for `fc00::/7`,
`fe80::/10` and `::1/128`, or disable IPv6 on the Docker network.

## 5. Build and run

Building the four images takes a few minutes the first time (the network image
compiles fingerprintx from source).

```bash
docker compose -f docker-compose.workers.yml --env-file workers.env up -d --build
docker compose -f docker-compose.workers.yml logs -f
```

Each worker should log `{"msg":"listening","queue":"aegis-scan-<engine>"}`. If one
logs `required tool missing`, that image's build is broken; rebuild it with
`--no-cache`. Run only some engines with, e.g.,
`... up -d --build discovery web` (leave `network` off until you want port scans).

Each container runs as a non-root user, with a read-only filesystem, no Linux
capabilities, `no-new-privileges`, resource limits, and 256 processes max.

## 6. Try it

1. On your PC, make sure `.env` has the same `DATABASE_URL` and `REDIS_URL`,
   then run `npm run dev:api` and `npm run dev:web`.
2. Sign in at http://localhost:3000, add **a domain you own** under
   Ownership, add the DNS TXT record it shows, and click **Check DNS record**.
3. On Assets, click **Find assets**. The discovery worker picks the job up
   within a few seconds; the list fills in when it finishes.
4. On any asset, click **Web**, **TLS** or **Ports** to run a check. Results
   appear in the **Findings** tab, worst first, with how to fix each one.
   (A **Ports** scan waits for an Admin to approve it on the Scans tab.)
5. **Stop all scans** in the header stops everything: queued jobs are dropped,
   and a running job stops at its next heartbeat (15 s).

## Updating

```bash
cd aegis && git pull
docker compose -f docker-compose.workers.yml --env-file workers.env up -d --build
```

## Scheduling & alerts

The recurring-scan tick and the new-exposure alert dispatch run **in the API
process**, not in these worker containers — that's where Redis and the SMTP /
WhatsApp config live. Keep the API running (on your PC for now, or wherever you
host it) for schedules to fire and alerts to send. The workers only consume the
scan queues. Slack and generic-webhook alert URLs are set per channel in the UI;
email and WhatsApp need `SMTP_URL` / `WHATSAPP_*` in the API's `.env`.

## What's not here yet

- API and dashboard hosting on the VPS (behind HTTPS) comes with a later phase.
- Per-job egress allow-lists (only the current job's target) need a network
  proxy per job; today's filter blocks private/reserved ranges for all jobs.
