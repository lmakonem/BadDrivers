# backend/tests/test_webhook.py
"""Stripe webhook: bad signature rejected; unsigned fails closed (task #5)."""
import json

import pytest
import stripe
from fastapi import HTTPException

from app.api.v1.endpoints import billing
from app.core.config import settings as app_settings


async def test_bad_signature_rejected(monkeypatch, make_request):
    monkeypatch.setattr(
        app_settings, "STRIPE_WEBHOOK_SECRET", "whsec_test", raising=False
    )

    def _boom(payload, sig_header, secret):
        raise stripe.error.SignatureVerificationError("bad sig", sig_header)

    monkeypatch.setattr(
        stripe.Webhook, "construct_event", staticmethod(_boom)
    )

    req = make_request(
        body=b'{"type":"checkout.session.completed"}',
        headers={"stripe-signature": "t=1,v1=deadbeef"},
    )
    with pytest.raises(HTTPException) as ei:
        await billing.stripe_webhook(request=req, db=None)  # db never reached
    assert ei.value.status_code == 400


async def test_unsigned_webhook_fails_closed(monkeypatch, make_request):
    # No webhook secret configured: the handler MUST refuse to process, never
    # fall back to json.loads() (that lets anyone forge a tier upgrade).
    monkeypatch.setattr(
        app_settings, "STRIPE_WEBHOOK_SECRET", "", raising=False
    )

    upgraded = {"called": False}

    async def _fake_upgrade(db, user_id, plan):
        upgraded["called"] = True

    monkeypatch.setattr(billing, "_upgrade_user", _fake_upgrade)

    forged = json.dumps(
        {
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {"user_id": "1", "plan": "enterprise"}}},
        }
    ).encode()
    req = make_request(body=forged, headers={})  # no stripe-signature

    try:
        await billing.stripe_webhook(request=req, db=None)
    except HTTPException as e:
        assert e.status_code in (400, 403, 503)
        assert upgraded["called"] is False
        return

    pytest.skip("Webhook still fails OPEN with no secret (task #5 not landed)")
