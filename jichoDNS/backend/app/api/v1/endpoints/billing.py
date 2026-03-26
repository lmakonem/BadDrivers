"""
Stripe billing endpoints — checkout, webhook, portal.

Uses Stripe Checkout for subscriptions. The webhook updates user tiers
in the database when payments succeed or subscriptions change.
"""

import logging
from typing import Optional

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.api.deps import get_current_user
from app.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()

# Configure Stripe
stripe.api_key = settings.STRIPE_SECRET_KEY

# Plan → Stripe Price ID mapping
# Replace these with real Stripe Price IDs after creating products in the dashboard
PLAN_PRICES = {
    "professional": settings.STRIPE_PRICE_PROFESSIONAL if hasattr(settings, "STRIPE_PRICE_PROFESSIONAL") else "price_professional_monthly",
}

PLAN_LIMITS = {
    "free": {"daily": 100, "monthly": 1000},
    "professional": {"daily": 10000, "monthly": 50000},
    "enterprise": {"daily": 999999, "monthly": 999999},
}


class CheckoutRequest(BaseModel):
    plan: str


class CheckoutResponse(BaseModel):
    url: str


class BillingPortalResponse(BaseModel):
    url: str


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout_session(
    body: CheckoutRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a Stripe Checkout session for upgrading to a paid plan.
    Returns the checkout URL to redirect the user to.
    """
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payments are not configured yet. Please contact sales.",
        )

    if body.plan not in PLAN_PRICES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan: {body.plan}. Available: {list(PLAN_PRICES.keys())}",
        )

    if current_user.tier == body.plan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You are already on this plan.",
        )

    price_id = PLAN_PRICES[body.plan]
    base_url = settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "https://jichosec.defendanddetect.com"

    try:
        # Check if user already has a Stripe customer ID
        # For simplicity, we create a new customer each time (Stripe deduplicates by email)
        session = stripe.checkout.Session.create(
            customer_email=current_user.email,
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=f"{base_url}/portal?upgraded=true",
            cancel_url=f"{base_url}/pricing?cancelled=true",
            metadata={
                "user_id": str(current_user.id),
                "plan": body.plan,
            },
            subscription_data={
                "metadata": {
                    "user_id": str(current_user.id),
                    "plan": body.plan,
                },
            },
        )

        return CheckoutResponse(url=session.url)

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating checkout: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Payment service error. Please try again.",
        )


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Stripe webhook endpoint. Receives events for subscription changes.
    Must be registered in the Stripe dashboard pointing to:
    https://jichosec.defendanddetect.com/api/v1/billing/webhook
    """
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")

    if settings.STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(
                payload, sig, settings.STRIPE_WEBHOOK_SECRET
            )
        except stripe.error.SignatureVerificationError:
            raise HTTPException(400, "Invalid webhook signature")
    else:
        # No webhook secret configured — parse payload directly (dev/test mode)
        import json
        event = json.loads(payload)

    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})

    logger.info(f"Stripe webhook: {event_type}")

    if event_type == "checkout.session.completed":
        # User completed checkout — upgrade their plan
        user_id = data.get("metadata", {}).get("user_id")
        plan = data.get("metadata", {}).get("plan")
        if user_id and plan:
            await _upgrade_user(db, int(user_id), plan)

    elif event_type == "customer.subscription.updated":
        # Subscription changed (upgrade/downgrade)
        meta = data.get("metadata", {})
        user_id = meta.get("user_id")
        plan = meta.get("plan")
        if user_id and plan and data.get("status") == "active":
            await _upgrade_user(db, int(user_id), plan)

    elif event_type in (
        "customer.subscription.deleted",
        "customer.subscription.paused",
    ):
        # Subscription cancelled or paused — downgrade to free
        meta = data.get("metadata", {})
        user_id = meta.get("user_id")
        if user_id:
            await _upgrade_user(db, int(user_id), "free")

    return {"received": True}


@router.post("/portal", response_model=BillingPortalResponse)
async def create_billing_portal(
    current_user: User = Depends(get_current_user),
):
    """
    Create a Stripe Customer Portal session for managing subscriptions.
    Only works if the user has an active Stripe subscription.
    """
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(503, "Payments not configured")

    base_url = settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "https://jichosec.defendanddetect.com"

    try:
        # Find customer by email
        customers = stripe.Customer.list(email=current_user.email, limit=1)
        if not customers.data:
            raise HTTPException(404, "No billing account found. Subscribe first.")

        session = stripe.billing_portal.Session.create(
            customer=customers.data[0].id,
            return_url=f"{base_url}/portal",
        )
        return BillingPortalResponse(url=session.url)

    except stripe.error.StripeError as e:
        logger.error(f"Stripe portal error: {e}")
        raise HTTPException(502, "Payment service error")


async def _upgrade_user(db: AsyncSession, user_id: int, plan: str):
    """Update the user's tier and API limits after a successful payment."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        logger.warning(f"Stripe webhook: user {user_id} not found")
        return

    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    user.tier = plan
    user.daily_api_limit = limits["daily"]
    user.monthly_api_limit = limits["monthly"]
    await db.flush()
    logger.info(f"User {user.email} upgraded to {plan}")
