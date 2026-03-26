"""
SQLAdmin panel — mounts at /admin on the FastAPI application.

Provides full CRUD for Users, Form Submissions, API Keys, and read-only
views for Indicators.  Authentication requires an admin user account.
"""

from sqladmin import Admin, ModelView, action
from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request
from starlette.responses import RedirectResponse

from app.core.database import engine, async_session_maker
from app.core.security import verify_password
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
        return request.session.get("admin_user_id") is not None


# ─── Model Views ──────────────────────────────────────────────────────────────

class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"
    icon = "fa-solid fa-users"

    column_list = [
        User.id, User.email, User.name, User.organization,
        User.tier, User.is_active, User.is_verified, User.is_admin,
        User.api_calls_today, User.api_calls_month, User.created_at,
    ]
    column_searchable_list = [User.email, User.name, User.organization]
    column_sortable_list = [
        User.id, User.email, User.tier, User.is_admin, User.created_at,
    ]
    column_default_sort = (User.created_at, True)  # newest first

    # Editable fields
    form_include_pk = False
    form_excluded_columns = [
        User.hashed_password, User.api_keys,
        User.api_calls_today, User.api_calls_month, User.last_api_call,
    ]

    # Admins can edit tier, is_active, is_admin, is_verified but not create users
    can_create = False
    can_delete = False

    column_labels = {
        User.tier: "Plan",
        User.is_admin: "Admin",
        User.is_verified: "Verified",
        User.is_active: "Active",
        User.api_calls_today: "API Today",
        User.api_calls_month: "API Month",
    }


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

    auth_backend = AdminAuth(secret_key=settings.SECRET_KEY)

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
