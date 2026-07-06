"""
migrate_findings.py — normalise old-schema findings to enterprise schema
Run: docker exec jichodns-api python3 /tmp/migrate_findings.py
"""
import asyncio, os, sys
sys.path.insert(0, '/app')

async def main():
    from app.services.elasticsearch import es_service
    await es_service.connect()
    es = es_service.client

    indices_resp = await es.cat.indices(format='json')
    findings_indices = [
        i['index'] for i in indices_resp
        if i['index'].endswith('_findings') and not i['index'].startswith('.')
    ]
    print(f'Found {len(findings_indices)} findings indices: {findings_indices}')

    total_migrated = 0
    for idx in findings_indices:
        resp = await es.search(index=idx, query={'match_all': {}}, size=500)
        hits = resp['hits']['hits']
        migrated_this = 0
        for h in hits:
            doc  = h['_source']
            did  = h['_id']
            # Only migrate old-schema docs (have affected_asset_value but not asset_value)
            needs_migration = 'affected_asset_value' in doc and not doc.get('asset_value')
            if not needs_migration:
                continue

            title = (doc.get('title') or '').lower()
            if 'ssl' in title or 'tls' in title or 'certificate' in title:
                cat = 'ssl'
            elif 'service' in title or 'port' in title or 'ftp' in title or 'rdp' in title or 'mysql' in title:
                cat = 'port'
            elif 'cve-' in title:
                cat = 'cve'
            elif 'http' in title and 'header' in title:
                cat = 'http_header'
            else:
                cat = 'misconfiguration'

            ts = doc.get('detected_at', '')
            patch = {
                'asset_value':    doc.get('affected_asset_value', ''),
                'asset_type':     doc.get('affected_asset_type', 'unknown'),
                'category':       cat,
                'status':         'open',
                'source':         'asm_scan',
                'first_seen':     ts,
                'last_seen':      ts,
                'epss_score':     None,
                'is_cisa_kev':    False,
                'is_exploitable': bool(doc.get('is_exploitable') or doc.get('exploit_available')),
                'remediation':    doc.get('remediation') or '',
                'references':     doc.get('references') or [],
            }
            await es.update(index=idx, id=did, body={'doc': patch})
            migrated_this += 1

        print(f'  {idx}: {migrated_this} migrated / {len(hits)} total')
        total_migrated += migrated_this

    print(f'\nDone. Total migrated: {total_migrated}')
    await es_service.close()

asyncio.run(main())
