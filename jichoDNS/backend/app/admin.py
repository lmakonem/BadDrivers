"""
SQLAdmin panel — mounts at /admin on the FastAPI application.

Provides full CRUD for Users, Form Submissions, API Keys, and read-only
views for Indicators.  Authentication requires an admin user account.
"""

from sqladmin import Admin, ModelView, action
from sqladmin.authentication import AuthenticationBackend
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from wtforms import SelectField, PasswordField

from app.core.database import engine, async_session_maker
from app.core.security import verify_password, hash_password
from app.models.user import User, APIKey
from app.models.form_submission import FormSubmission


# ─── Auth backend ─────────────────────────────────────────────────────────────

class AdminAuth(AuthenticationBackend):
    """Authenticate admin users via the existing User table."""

    async def login(self, request: Request) -> bool:
        form = await request.form()
        email = form.get("username", "")
        password = form.get("password", "")

        from sqlalchemy import select

        async with async_session_maker() as session:
            result = await session.execute(
                select(User).where(User.email == str(email))
            )
            user = result.scalar_one_or_none()

            if (
                user
                and user.is_admin
                and user.is_active
                and user.hashed_password
                and verify_password(str(password), user.hashed_password)
            ):
                request.session.update({"admin_user_id": str(user.id)})
                return True

        return False

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        """Re-validate the admin on EVERY request.

        A present session cookie is NOT sufficient: the referenced user must
        still exist, be active, and retain admin privileges. This mirrors
        get_current_admin so that a demoted or deactivated admin loses panel
        access immediately, rather than keeping full CRUD for the remaining
        cookie lifetime.
        """
        admin_user_id = request.session.get("admin_user_id")
        if not admin_user_id:
            return False

        from sqlalchemy import select

        try:
            user_id = int(admin_user_id)
        except (TypeError, ValueError):
            request.session.clear()
            return False

        async with async_session_maker() as session:
            result = await session.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one_or_none()

        if user and user.is_active and user.is_admin:
            return True

        # Stale / revoked session — force re-login.
        request.session.clear()
        return False


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
        """Hash password on create/update."""
        pw = data.pop("set_password", None)
        if pw:
            model.hashed_password = hash_password(pw)
        elif is_created and not model.hashed_password:
            model.hashed_password = hash_password("changeme123")

    async def on_model_delete(self, model, request):
        """Handle user deletion — delete related records first."""
        pass  # cascade="all, delete-orphan" handles api_keys

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
        ),
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
