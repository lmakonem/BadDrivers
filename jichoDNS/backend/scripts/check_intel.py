"""Quick audit: which clients have credential/IOC matches in platform datasets."""
import asyncio, sys, psycopg2, os
sys.path.insert(0, '/app')

async def go():
    from app.services.elasticsearch import es_service
    await es_service.connect()
    es = es_service.client

    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    cur = conn.cursor()
    cur.execute("""
        SELECT ac.id, ac.name, ac.country_code,
               array_agg(DISTINCT s->>'value') FILTER (WHERE s->>'type'='domain') AS domains
        FROM asm_clients ac
        JOIN asm_discovery_groups ag ON ag.client_id = ac.id
        CROSS JOIN LATERAL jsonb_array_elements(ag.seeds::jsonb) AS s
        GROUP BY ac.id, ac.name, ac.country_code ORDER BY ac.id
    """)
    clients = {r[0]: (r[1], r[2], r[3] or []) for r in cur.fetchall()}
    conn.close()

    print('=== CREDENTIAL MATCHES per client ===')
    cred_clients = {}
    for cid, (name, cc, domains) in clients.items():
        bare = list(set(d.lstrip('www.') for d in domains if d))
        if not bare:
            continue
        should = [{'term': {'domain': d}} for d in bare]
        resp = await es.count(index='credential_exposures', body={'query': {'bool': {'should': should, 'minimum_should_match': 1}}})
        cnt = resp['count']
        if cnt > 0:
            cred_clients[cid] = cnt
            print(f'  id={cid:3d} {name[:33]:<33} {cc} creds={cnt} domains={bare[:2]}')
    print(f'Total clients with creds: {len(cred_clients)}')

    print()
    print('=== IOC MATCHES per client ===')
    ioc_clients = {}
    for cid, (name, cc, domains) in clients.items():
        bases = list(set(
            d.lstrip('www.').split('.')[0]
            for d in domains if d and len(d.lstrip('www.').split('.')[0]) >= 4
        ))
        if not bases:
            continue
        should = [{'wildcard': {'indicator': f'*{b}*'}} for b in bases[:3]]
        resp = await es.count(index='iocs', body={'query': {'bool': {
            'should': should, 'minimum_should_match': 1,
            'filter': [{'term': {'active': True}}]
        }}})
        cnt = resp['count']
        if cnt > 0:
            ioc_clients[cid] = cnt
            print(f'  id={cid:3d} {name[:33]:<33} {cc} iocs={cnt} bases={bases[:2]}')
    print(f'Total clients with IOC matches: {len(ioc_clients)}')

asyncio.run(go())
