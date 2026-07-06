#!/usr/bin/env python3
"""
One-shot, idempotent backfill for the ownership/IDOR + credential-redaction
hardening. Run ONCE after deploying the code:

    LEGACY_DATA_OWNER_ID=1 python -m scripts.backfill_ownership_and_redact
    # or: python backend/scripts/backfill_ownership_and_redact.py

Does three things against Elasticsearch (settings.ELASTICSEARCH_URL):
  1. Stamp `owner_user_id` on `threat_reports` docs that lack it.
  2. Stamp `owner_user_id` on `brand_monitors` docs that lack it.
  3. Purge plaintext creds in `credential_exposures`:
       - delete the `password` field on every doc,
       - for legacy password_type=="plaintext" docs whose `password_hash`
         still holds the raw plaintext, replace it with sha256(plaintext).
"""

import asyncio
import hashlib
import os

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk, async_scan

# Reuse the app's configured ES URL.
try:
    from app.core.config import settings
    ES_URL = settings.ELASTICSEARCH_URL
except Exception:
    ES_URL = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")

OWNER_ID = int(os.environ.get("LEGACY_DATA_OWNER_ID", "1"))


async def _stamp_owner(es: AsyncElasticsearch, index: str) -> None:
    if not await es.indices.exists(index=index):
        print(f"[skip] index {index} does not exist")
        return
    resp = await es.update_by_query(
        index=index,
        conflicts="proceed",
        refresh=True,
        body={
            "query": {"bool": {"must_not": [{"exists": {"field": "owner_user_id"}}]}},
            "script": {
                "lang": "painless",
                "source": "if (!ctx._source.containsKey('owner_user_id') "
                          "|| ctx._source.owner_user_id == null) "
                          "{ ctx._source.owner_user_id = params.owner; }",
                "params": {"owner": OWNER_ID},
            },
        },
    )
    print(f"[owner] {index}: updated={resp.get('updated')} to owner_user_id={OWNER_ID}")


async def _redact_credentials(es: AsyncElasticsearch) -> None:
    index = "credential_exposures"
    if not await es.indices.exists(index=index):
        print(f"[skip] index {index} does not exist")
        return

    actions = []
    scanned = rehashed = stripped = 0
    async for hit in async_scan(
        es, index=index,
        query={"query": {"exists": {"field": "password"}}},
        _source=["password", "password_hash", "password_type"],
    ):
        scanned += 1
        src = hit["_source"]
        doc = {"password": None}          # remove plaintext (set null then script-remove below)
        if src.get("password_type") == "plaintext":
            pw = src.get("password") or src.get("password_hash") or ""
            doc["password_hash"] = hashlib.sha256(pw.encode()).hexdigest()
            rehashed += 1
        stripped += 1
        actions.append({
            "_op_type": "update", "_index": index, "_id": hit["_id"],
            "script": {
                "lang": "painless",
                "source": ("ctx._source.remove('password');"
                           "if (params.rehash != null) { ctx._source.password_hash = params.rehash; }"),
                "params": {"rehash": doc.get("password_hash")},
            },
        })
        if len(actions) >= 500:
            await async_bulk(es, actions, raise_on_error=False)
            actions = []
    if actions:
        await async_bulk(es, actions, raise_on_error=False)
    await es.indices.refresh(index=index)
    print(f"[creds] scanned={scanned} password-stripped={stripped} rehashed_plaintext={rehashed}")


async def main() -> None:
    es = AsyncElasticsearch([ES_URL], verify_certs=False, request_timeout=120)
    try:
        await _stamp_owner(es, "threat_reports")
        await _stamp_owner(es, "brand_monitors")
        await _redact_credentials(es)
    finally:
        await es.close()


if __name__ == "__main__":
    asyncio.run(main())
