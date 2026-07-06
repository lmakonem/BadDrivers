"""
batch_scan_all.py — Controlled ASM scan dispatcher
Run inside jichodns-worker: python3 /app/scripts/batch_scan_all.py
"""
import os, sys, time, psycopg2
sys.path.insert(0, "/app")

BATCH_SIZE  = 5
BATCH_DELAY = 60   # seconds between batches

# ── Celery sender (no app.worker import — avoids blocking init) ───────────────
REDIS_URL = os.environ.get("REDIS_URL", "redis://:jDNS_rd_Zn7v4Kg2Dx8pLs1U@hichodns-redis:6379/0")
from celery import Celery
sender = Celery("batch_sender", broker=REDIS_URL)

# ── DB: get all unscanned clients with their seed domains ─────────────────────
conn = psycopg2.connect(os.environ["DATABASE_URL"])
cur  = conn.cursor()
cur.execute("""
    SELECT ac.id, ac.name, ac.country_code,
           array_agg(DISTINCT s->>'value') FILTER (WHERE s->>'value' IS NOT NULL)
    FROM asm_clients ac
    JOIN asm_discovery_groups ag ON ag.client_id = ac.id AND ag.is_active = TRUE
    CROSS JOIN LATERAL jsonb_array_elements(ag.seeds::jsonb) AS s
    WHERE ac.total_assets = 0 AND ac.is_active = TRUE
      AND s->>'type' IN ('domain','ip_range','asn','org_name','email_domain')
    GROUP BY ac.id, ac.name, ac.country_code
    ORDER BY ac.id ASC
""")
clients = cur.fetchall()
conn.close()

total = len(clients)
print(f"[batch_scan] {total} unscanned clients", flush=True)
print(f"[batch_scan] batch_size={BATCH_SIZE}  delay={BATCH_DELAY}s\n", flush=True)

dispatched = 0
for i in range(0, total, BATCH_SIZE):
    batch = clients[i:i+BATCH_SIZE]
    bn = i // BATCH_SIZE + 1
    tb = (total + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"[batch_scan] === Batch {bn}/{tb} ===", flush=True)
    for cid, name, cc, domains in batch:
        domains = [d for d in (domains or []) if d]
        if not domains:
            print(f"  SKIP  id={cid:3d} {name}", flush=True)
            continue
        sender.send_task(
            "app.worker.run_asm_discovery",
            kwargs={"client_id": cid, "domains": domains},
        )
        dispatched += 1
        print(f"  SENT  id={cid:3d} {name:<40} {cc}  {domains[:1]}", flush=True)
    if i + BATCH_SIZE < total:
        print(f"  sleeping {BATCH_DELAY}s...\n", flush=True)
        time.sleep(BATCH_DELAY)

print(f"\n[batch_scan] Done — {dispatched}/{total} dispatched.", flush=True)
