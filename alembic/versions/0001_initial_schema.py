from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("base_url", sa.String(500), nullable=False, server_default=""),
        sa.Column("notes", sa.Text()),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("url_template", sa.String(2000), nullable=False),
        sa.Column("sample_url", sa.String(2000), nullable=False),
        sa.Column("request_body", postgresql.JSONB()),
        sa.Column("request_headers", postgresql.JSONB()),
        sa.Column("response_status", sa.Integer()),
        sa.Column("response_size", sa.Integer()),
        sa.Column("content_type", sa.String(255)),
        sa.Column("mutable_params", postgresql.JSONB()),
        sa.Column("auth_params", postgresql.JSONB()),
        sa.Column("seen_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("first_seen", postgresql.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("target_id", "method", "url_template"),
    )
    op.create_index("idx_endpoints_target", "endpoints", ["target_id"])
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("started_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", postgresql.TIMESTAMP(timezone=True)),
        sa.Column("status", sa.String(50), server_default="running", nullable=False),
        sa.Column("checks_enabled", postgresql.ARRAY(sa.Text())),
        sa.Column("triage_enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("config", postgresql.JSONB()),
        sa.Column("summary", postgresql.JSONB()),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("endpoints.id")),
        sa.Column("check_name", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("poc_curl", sa.Text()),
        sa.Column("remediation", sa.Text()),
        sa.Column("triage_status", sa.String(50), server_default="pending", nullable=False),
        sa.Column("triage_notes", sa.Text()),
        sa.Column("llm_enriched", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_findings_scan", "findings", ["scan_id"])
    op.create_index("idx_findings_severity", "findings", ["severity"])
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_label", sa.String(100), nullable=False),
        sa.Column("cookies", postgresql.JSONB()),
        sa.Column("storage", postgresql.JSONB()),
        sa.Column("headers", postgresql.JSONB()),
        sa.Column("valid_until", postgresql.TIMESTAMP(timezone=True)),
        sa.Column("refresh_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", postgresql.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    for table in ["sessions", "findings", "scans", "endpoints", "targets"]:
        op.drop_table(table)
