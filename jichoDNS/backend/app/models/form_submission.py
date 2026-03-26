"""Form submission models for persisting contact, demo, quote, and newsletter data."""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB

from .base import Base, TimestampMixin


class FormSubmission(Base, TimestampMixin):
    """
    Stores all form submissions (demo, contact, quote, newsletter).

    The `form_type` column distinguishes between submission types and
    `payload` stores the type-specific fields as JSON.
    """

    __tablename__ = "form_submissions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Type: demo | contact | quote | newsletter
    form_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # Submitter info (common across all types)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Workflow status: unread | read | replied | archived
    status: Mapped[str] = mapped_column(String(32), default="unread", index=True)

    # Unique submission ID (UUID exposed to the user)
    submission_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)

    # Full payload — every field the user submitted
    payload: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_form_submissions_type_status", "form_type", "status"),
    )

    def __repr__(self) -> str:
        return f"<FormSubmission {self.form_type} from {self.email}>"
