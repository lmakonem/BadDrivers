"""
SQLAdmin panel — mounts at /admin on the FastAPI application.

Provides full CRUD for Users, Form Submissions, API Keys, and read-only
views for Indicators.  Authentication requires an admin user account.
"""

from typing import Optional

from sqladmin import Admin, ModelView, action
from sqladmin.authentication import AuthenticationBackend
from sqlalchemy import select
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from wtforms import SelectField, PasswordField

from app.core.database import engine, async_session_maker
from app.core.security import (
    verify_password,
    hash_password,
    dummy_verify,
    decode_token,
    get_token_subject,
)
from app.core.ratelimit import (
    check_login_allowed,
    record_login_failure,
    clear_login_failures,
    client_ip,
)
from app.models.user import User, APIKey
from app.models.form_submission import FormSubmission


# ─── Shared admin-resolution helpers ──────────────────────────────────────────

async def _active_admin_by_id(user_id: int) -> Optional[User]:
    """Return the user iff they exist, are active, and are an admin."""
    async with async_session_maker() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    return user if (user and user.is_active and user.is_admin) else None


async def _admin_from_jwt_cookie(request: Request) -> Optional[User]:
    """Resolve an active admin from the portal ``jichodns_access_token`` JWT cookie.

    This is what makes the panel single-sign-on with the portal: a user already
    logged into the portal carries a valid access token, so they are not asked to
    log in again. Returns None for a missing/invalid/expired token or a non-admin.
    """
    token = request.cookies.get("jichodns_access_token")
    if not token:
        return None
    payload = decode_token(token, require_type="access")
    if not payload:
        return None
    uid = get_token_subject(payload)
    if uid is None:
        return None
    return await _active_admin_by_id(uid)


# ─── Auth backend ─────────────────────────────────────────────────────────────

class AdminAuth(AuthenticationBackend):
    """Authenticate admin users via the existing User table."""

    async def login(self, request: Request) -> bool:
        form = await request.form()
        email = str(form.get("username", ""))
        password = str(form.get("password", ""))
        ip = client_ip(request)

        # Brute-force lockout (per-account + per-IP) — the same Redis limiter that
        # already guards /api/v1/auth/login. Without this the panel login would be
        # the only unthrottled login on the platform once /admin is publicly routed.
        if await check_login_allowed(email, ip) is not None:
            return False

        from sqlalchemy import select

        async with async_session_maker() as session:
            result = await session.execute(
                select(User).where(User.email == email)
            )
            user = result.scalar_one_or_none()

        # Always spend one bcrypt verify so a missing / non-admin account is
        # timing-indistinguishable from a wrong password (no user enumeration).
        if user and user.hashed_password:
            password_ok = verify_password(password, user.hashed_password)
        else:
            dummy_verify()
            password_ok = False

        if user and user.is_admin and user.is_active and password_ok:
            await clear_login_failures(email, ip)
            request.session.update({"admin_user_id": str(user.id)})
            return True

        await record_login_failure(email, ip)
        return False

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        """Grant panel access to an active admin, re-validated on EVERY request.

        Two accepted credentials:

        1. The sqladmin session cookie (set by ``login`` or by SSO below). It is
           ``SameSite=Strict``, so its presence proves a same-site request — safe
           for state-changing action routes.
        2. Single sign-on from the portal: a valid ``jichodns_access_token`` JWT
           cookie belonging to an active admin, so an admin already logged into
           the portal is not asked to log in again.

        The portal JWT cookie is ``SameSite=Lax`` (frontend ``lib/auth.ts``), so
        it WOULD ride a cross-site top-level GET. sqladmin registers its bulk
        actions as GET routes with no CSRF token, so to avoid re-opening that
        CSRF hole we accept the JWT ONLY for safe (GET/HEAD, non-``/action/``)
        requests, and immediately upgrade it to a Strict sqladmin session. Every
        subsequent request — including actions and form POSTs — is then
        authenticated by path 1, never by the Lax cookie. A cross-site GET to an
        action URL carries only the Lax JWT (Strict session not sent), is not a
        "safe" request, so it is rejected.

        A present cookie is never sufficient on its own: the referenced user must
        still exist, be active, and retain admin — a demoted/deactivated admin
        loses access immediately.
        """
        # ── Path 1: existing sqladmin session (Strict cookie) ────────────────
        admin_user_id = request.session.get("admin_user_id")
        if admin_user_id:
            try:
                user_id = int(admin_user_id)
            except (TypeError, ValueError):
                request.session.clear()
            else:
                if await _active_admin_by_id(user_id):
                    return True
                request.session.clear()  # stale / revoked

        # ── Path 2: portal SSO via JWT cookie — SAFE requests only ───────────
        is_safe = (
            request.method in ("GET", "HEAD")
            and "/action/" not in request.url.path
        )
        if is_safe:
            admin = await _admin_from_jwt_cookie(request)
            if admin:
                # Upgrade to a Strict sqladmin session so all subsequent
                # (incl. state-changing) requests authenticate via path 1.
                request.session.update({"admin_user_id": str(admin.id)})
                return True

        return False


# ─── SSO login redirect ───────────────────────────────────────────────────────

class SSOLoginRedirect(BaseHTTPMiddleware):
    """Send an already-authenticated admin straight into the panel if they land
    on ``/admin/login`` (e.g. a bookmark or the portal link after logging in),
    instead of showing the login form again.

    Loop-safe: it redirects ONLY a fully-validated active admin (session or
    portal JWT). A non-admin with a portal token is NOT redirected, so it cannot
    ping-pong between /admin (denied) and /admin/login.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method in ("GET", "HEAD") and request.url.path.rstrip("/") == "/admin/login":
            authed = False
            uid = request.session.get("admin_user_id")
            if uid:
                try:
                    authed = bool(await _active_admin_by_id(int(uid)))
                except (TypeError, ValueError):
                    authed = False
            if not authed:
                authed = bool(await _admin_from_jwt_cookie(request))
            if authed:
                return RedirectResponse("/admin", status_code=302)
        return await call_next(request)


# ─── Model Views ──────────────────────────────────────────────────────────────

class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"
    icon = "fa-solid fa-users"

    column_list = [
        User.id, User.email, User.name, User.organization,
        User.tier, User.is_active, User.is_verified, User.is_admin,
        User.daily_api_limit, User.monthly_api_limit,
        User.api_calls_today, User.api_calls_month, User.created_at,
    ]
    column_searchable_list = [User.email, User.name, User.organization]
    column_sortable_list = [
        User.id, User.email, User.tier, User.is_admin, User.created_at,
    ]
    column_default_sort = (User.created_at, True)

    form_include_pk = False
    form_excluded_columns = [
        # hashed_password is NEVER a raw form field — the "Set Password" extra
        # field is the only write path. Rendering it would disclose the bcrypt
        # hash and (because SQLAdmin applies raw form data AFTER on_model_change)
        # silently clobber a fresh set_password on edit / null it on create.
        User.hashed_password,
        User.api_keys,
        User.api_calls_today, User.api_calls_month, User.last_api_call,
    ]

    can_create = True
    can_delete = True
    can_edit = True

    # Override form to add a plain password field for creation
    form_extra_fields = {
        "set_password": PasswordField("Set Password (leave blank to keep existing)"),
    }

    async def on_model_change(self, data, model, is_created, request):
        """Hash the chosen password on create/update.

        A password is REQUIRED on create — we never fall back to a fixed default.
        A hardcoded default (formerly "changeme123") would provision a
        publicly-known credential, and the account is loginable via
        /api/v1/auth/login, not just the panel.
        """
        pw = data.pop("set_password", None)
        if pw:
            model.hashed_password = hash_password(pw)
        elif is_created and not model.hashed_password:
            raise ValueError(
                "A password is required when creating a user "
                "(use the 'Set Password' field)."
            )

    async def on_model_delete(self, model, request):
        """Refuse to delete the last active admin — would lock everyone out.

        (api_keys are handled by the relationship cascade.)
        """
        if getattr(model, "is_admin", False):
            from sqlalchemy import select, func

            async with async_session_maker() as session:
                remaining = await session.scalar(
                    select(func.count(User.id)).where(
                        User.is_admin.is_(True),
                        User.is_active.is_(True),
                        User.id != model.id,
                    )
                )
            if not remaining:
                raise ValueError("Cannot delete the last active admin account.")

    column_labels = {
        User.tier: "Plan",
        User.is_admin: "Admin",
        User.is_verified: "Verified",
        User.is_active: "Active",
        User.daily_api_limit: "Daily Limit",
        User.monthly_api_limit: "Monthly Limit",
        User.api_calls_today: "API Today",
        User.api_calls_month: "API Month",
    }

    # Dropdown choices for tier and API limits
    form_overrides = {
        "tier": SelectField,
        "daily_api_limit": SelectField,
        "monthly_api_limit": SelectField,
    }
    form_args = {
        "tier": {
            "choices": [
                ("free", "Free (100/day, 3k/month)"),
                ("professional", "Professional (10k/day, 50k/month)"),
                ("enterprise", "Enterprise (unlimited)"),
            ],
            "coerce": str,
        },
        "daily_api_limit": {
            "choices": [
                ("100", "100 (Free)"),
                ("1000", "1,000"),
                ("5000", "5,000"),
                ("10000", "10,000 (Pro)"),
                ("50000", "50,000"),
                ("100000", "100,000"),
                ("999999", "Unlimited (Enterprise)"),
            ],
            "coerce": int,
        },
        "monthly_api_limit": {
            "choices": [
                ("3000", "3,000 (Free)"),
                ("10000", "10,000"),
                ("50000", "50,000 (Pro)"),
                ("100000", "100,000"),
                ("500000", "500,000"),
                ("999999", "Unlimited (Enterprise)"),
            ],
            "coerce": int,
        },
    }

    # Bulk actions
    @action(
        name="upgrade_pro",
        label="Upgrade to Professional",
        confirmation_message="Upgrade selected users to Professional plan?",
        add_in_list=True,
    )
    async def action_upgrade_pro(self, request: Request):
        pks = request.query_params.get("pks", "").split(",")
        if pks and pks[0]:
            from sqlalchemy import select
            async with async_session_maker() as session:
                for pk in pks:
                    result = await session.execute(
                        select(User).where(User.id == int(pk))
                    )
                    user = result.scalar_one_or_none()
                    if user:
                        user.tier = "professional"
                        user.daily_api_limit = 10000
                        user.monthly_api_limit = 50000
                await session.commit()

    @action(
        name="upgrade_enterprise",
        label="Upgrade to Enterprise",
        confirmation_message="Upgrade selected users to Enterprise plan?",
        add_in_list=True,
    )
    async def action_upgrade_enterprise(self, request: Request):
        pks = request.query_params.get("pks", "").split(",")
        if pks and pks[0]:
            from sqlalchemy import select
            async with async_session_maker() as session:
                for pk in pks:
                    result = await session.execute(
                        select(User).where(User.id == int(pk))
                    )
                    user = result.scalar_one_or_none()
                    if user:
                        user.tier = "enterprise"
                        user.daily_api_limit = 999999
                        user.monthly_api_limit = 999999
                await session.commit()

    @action(
        name="downgrade_free",
        label="Downgrade to Free",
        confirmation_message="Downgrade selected users to Free plan?",
        add_in_list=True,
    )
    async def action_downgrade_free(self, request: Request):
        pks = request.query_params.get("pks", "").split(",")
        if pks and pks[0]:
            from sqlalchemy import select
            async with async_session_maker() as session:
                for pk in pks:
                    result = await session.execute(
                        select(User).where(User.id == int(pk))
                    )
                    user = result.scalar_one_or_none()
                    if user:
                        user.tier = "free"
                        user.daily_api_limit = 100
                        user.monthly_api_limit = 3000
                await session.commit()

    @action(
        name="deactivate",
        label="Deactivate Users",
        confirmation_message="Deactivate selected users?",
        add_in_list=True,
    )
    async def action_deactivate(self, request: Request):
        pks = request.query_params.get("pks", "").split(",")
        if pks and pks[0]:
            from sqlalchemy import select
            async with async_session_maker() as session:
                for pk in pks:
                    result = await session.execute(
                        select(User).where(User.id == int(pk))
                    )
                    user = result.scalar_one_or_none()
                    if user:
                        user.is_active = False
                await session.commit()


class FormSubmissionAdmin(ModelView, model=FormSubmission):
    name = "Submission"
    name_plural = "Form Submissions"
    icon = "fa-solid fa-inbox"

    column_list = [
        FormSubmission.id, FormSubmission.form_type, FormSubmission.email,
        FormSubmission.name, FormSubmission.status, FormSubmission.created_at,
    ]
    column_searchable_list = [FormSubmission.email, FormSubmission.name]
    column_sortable_list = [
        FormSubmission.id, FormSubmission.form_type,
        FormSubmission.status, FormSubmission.created_at,
    ]
    column_default_sort = (FormSubmission.created_at, True)

    # Admins can view and update status, but not create or delete
    can_create = False
    can_delete = False

    # Detail view shows the full JSON payload
    column_details_list = [
        FormSubmission.id, FormSubmission.form_type, FormSubmission.email,
        FormSubmission.name, FormSubmission.status, FormSubmission.submission_id,
        FormSubmission.payload, FormSubmission.created_at,
    ]

    column_labels = {
        FormSubmission.form_type: "Type",
        FormSubmission.status: "Status",
    }

    @action(
        name="mark_read",
        label="Mark as Read",
        confirmation_message="Mark selected submissions as read?",
        add_in_list=True,
    )
    async def action_mark_read(self, request: Request):
        pks = request.query_params.get("pks", "").split(",")
        if pks and pks[0]:
            from sqlalchemy import select
            async with async_session_maker() as session:
                for pk in pks:
                    result = await session.execute(
                        select(FormSubmission).where(FormSubmission.id == int(pk))
                    )
                    sub = result.scalar_one_or_none()
                    if sub:
                        sub.status = "read"
                await session.commit()

    @action(
        name="mark_replied",
        label="Mark as Replied",
        confirmation_message="Mark selected submissions as replied?",
        add_in_list=True,
    )
    async def action_mark_replied(self, request: Request):
        pks = request.query_params.get("pks", "").split(",")
        if pks and pks[0]:
            from sqlalchemy import select
            async with async_session_maker() as session:
                for pk in pks:
                    result = await session.execute(
                        select(FormSubmission).where(FormSubmission.id == int(pk))
                    )
                    sub = result.scalar_one_or_none()
                    if sub:
                        sub.status = "replied"
                await session.commit()

    @action(
        name="archive",
        label="Archive",
        confirmation_message="Archive selected submissions?",
        add_in_list=True,
    )
    async def action_archive(self, request: Request):
        pks = request.query_params.get("pks", "").split(",")
        if pks and pks[0]:
            from sqlalchemy import select
            async with async_session_maker() as session:
                for pk in pks:
                    result = await session.execute(
                        select(FormSubmission).where(FormSubmission.id == int(pk))
                    )
                    sub = result.scalar_one_or_none()
                    if sub:
                        sub.status = "archived"
                await session.commit()


class APIKeyAdmin(ModelView, model=APIKey):
    name = "API Key"
    name_plural = "API Keys"
    icon = "fa-solid fa-key"

    column_list = [
        APIKey.id, APIKey.key_prefix, APIKey.name,
        APIKey.is_active, APIKey.usage_count, APIKey.last_used_at, APIKey.created_at,
    ]
    column_searchable_list = [APIKey.name, APIKey.key_prefix]
    column_sortable_list = [APIKey.id, APIKey.is_active, APIKey.usage_count]
    column_default_sort = (APIKey.created_at, True)

    can_create = False
    can_delete = False

    column_labels = {
        APIKey.key_prefix: "Key Prefix",
        APIKey.usage_count: "Usage",
    }


# ─── Setup ────────────────────────────────────────────────────────────────────

def setup_admin(app):
    """Mount the SQLAdmin panel on the FastAPI app at /admin."""
    from app.core.config import settings

    # Separate signing key for the admin session cookie; falls back to SECRET_KEY.
    session_secret = settings.SESSION_SECRET_KEY or settings.SECRET_KEY
    auth_backend = AdminAuth(secret_key=session_secret)

    # SQLAdmin defaults the session cookie to a 14-day lifetime. authenticate()
    # re-validates against the DB on every request, but shortening the cookie to
    # 8 hours further limits the window for a stolen/stale session cookie.
    ADMIN_SESSION_MAX_AGE = 8 * 60 * 60  # 8 hours, in seconds
    auth_backend.middlewares = [
        Middleware(
            SessionMiddleware,
            secret_key=session_secret,
            max_age=ADMIN_SESSION_MAX_AGE,
            # SameSite=Strict withholds the admin cookie from ALL cross-site
            # requests. This is the primary CSRF defense: SQLAdmin 0.20.1 ships
            # no CSRF tokens and registers its bulk actions (upgrade tier,
            # deactivate user, ...) as *GET* routes, so a SameSite=Lax cookie
            # would ride a lured top-level navigation and mutate the DB.
            same_site="strict",
            # Secure flag — the panel is only ever served over HTTPS (Cloudflare
            # tunnel), so the session cookie must never travel in cleartext.
            https_only=True,
        ),
        # Runs AFTER SessionMiddleware (inner) so request.session is populated:
        # SSO-redirects an already-authenticated admin away from the login form.
        Middleware(SSOLoginRedirect),
    ]

    admin = Admin(
        app,
        engine,
        authentication_backend=auth_backend,
        title="JichoDNS Admin",
        base_url="/admin",
    )

    admin.add_view(UserAdmin)
    admin.add_view(FormSubmissionAdmin)
    admin.add_view(APIKeyAdmin)
