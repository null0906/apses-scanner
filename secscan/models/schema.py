from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import ARRAY, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    endpoints: Mapped[list[Endpoint]] = relationship(back_populates="target", cascade="all, delete-orphan")
    sessions: Mapped[list[Session]] = relationship(back_populates="target", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("target_id", "method", "url_template"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    url_template: Mapped[str] = mapped_column(String(2000), nullable=False)
    sample_url: Mapped[str] = mapped_column(String(2000), nullable=False)
    request_body: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    request_headers: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mutable_params: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)
    auth_params: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)
    seen_count: Mapped[int] = mapped_column(Integer, server_default="1", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    target: Mapped[Target] = relationship(back_populates="endpoints")
    findings: Mapped[list[Finding]] = relationship(back_populates="endpoint")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    user_label: Mapped[str] = mapped_column(String(100), default="default", nullable=False)
    cookies: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)
    storage: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    headers: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    refresh_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    target: Mapped[Target] = relationship(back_populates="sessions")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(50), server_default="running", nullable=False)
    checks_enabled: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    triage_enabled: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id"), nullable=True)
    check_name: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    poc_curl: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    triage_status: Mapped[str] = mapped_column(String(50), server_default="pending", nullable=False)
    triage_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_enriched: Mapped[bool] = mapped_column(Boolean, server_default="false", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    endpoint: Mapped[Endpoint] = relationship(back_populates="findings")
