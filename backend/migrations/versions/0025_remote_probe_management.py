"""Persist probe inventory, dispatched tasks, and idempotent observations."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0025_remote_probe_management"
down_revision = "0024_orion_product_identity"
branch_labels = None
depends_on = None
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "remote_probes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("address", sa.String(45), nullable=False),
        sa.Column("api_port", sa.Integer(), server_default="9443", nullable=False),
        sa.Column(
            "network_zone_id",
            sa.Uuid(),
            sa.ForeignKey("network_zones.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("certificate_sha256", sa.String(64), nullable=False),
        sa.Column("certificate_pem", sa.Text(), nullable=False),
        sa.Column("encrypted_token", sa.Text(), server_default="", nullable=False),
        sa.Column("status", sa.String(16), server_default="pairing", nullable=False),
        sa.Column("capabilities", JSON, server_default="[]", nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column(
            "acknowledged_cursor", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("pending_ack_cursor", sa.Integer()),
        sa.Column(
            "created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("address", "api_port", name="uq_remote_probe_address_port"),
        sa.CheckConstraint(
            "status IN ('pairing', 'active', 'disabled', 'revoked')",
            name="ck_remote_probe_status",
        ),
    )
    op.create_index("ix_remote_probes_status", "remote_probes", ["status"])
    op.create_index("ix_remote_probes_zone", "remote_probes", ["network_zone_id"])

    op.create_table(
        "remote_probe_tasks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "probe_id",
            sa.Uuid(),
            sa.ForeignKey("remote_probes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "run_id", sa.Uuid(), sa.ForeignKey("scan_runs.id", ondelete="SET NULL")
        ),
        sa.Column("kind", sa.String(12), nullable=False),
        sa.Column("request_payload", JSON, nullable=False),
        sa.Column("status", sa.String(20), server_default="queued", nullable=False),
        sa.Column("error", sa.String(80), server_default="", nullable=False),
        sa.Column(
            "created_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "kind IN ('tls', 'ssh', 'ipsec', 'dns')", name="ck_remote_probe_task_kind"
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted')",
            name="ck_remote_probe_task_status",
        ),
    )
    op.create_index(
        "ix_remote_probe_tasks_probe_id", "remote_probe_tasks", ["probe_id"]
    )
    op.create_index("ix_remote_probe_tasks_run_id", "remote_probe_tasks", ["run_id"])
    op.create_index("ix_remote_probe_tasks_status", "remote_probe_tasks", ["status"])
    op.create_index(
        "ix_remote_probe_tasks_probe_status",
        "remote_probe_tasks",
        ["probe_id", "status"],
    )

    op.create_table(
        "remote_probe_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "probe_id",
            sa.Uuid(),
            sa.ForeignKey("remote_probes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("cursor", sa.Integer(), nullable=False),
        sa.Column(
            "task_id",
            sa.Uuid(),
            sa.ForeignKey("remote_probe_tasks.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("payload", JSON, nullable=False),
        sa.UniqueConstraint("probe_id", "event_id", name="uq_remote_probe_event_id"),
        sa.UniqueConstraint("probe_id", "cursor", name="uq_remote_probe_event_cursor"),
    )
    op.create_index(
        "ix_remote_probe_events_probe_id", "remote_probe_events", ["probe_id"]
    )
    op.create_index(
        "ix_remote_probe_events_received", "remote_probe_events", ["received_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_remote_probe_events_received", table_name="remote_probe_events")
    op.drop_index("ix_remote_probe_events_probe_id", table_name="remote_probe_events")
    op.drop_table("remote_probe_events")
    op.drop_index("ix_remote_probe_tasks_probe_status", table_name="remote_probe_tasks")
    op.drop_index("ix_remote_probe_tasks_status", table_name="remote_probe_tasks")
    op.drop_index("ix_remote_probe_tasks_run_id", table_name="remote_probe_tasks")
    op.drop_index("ix_remote_probe_tasks_probe_id", table_name="remote_probe_tasks")
    op.drop_table("remote_probe_tasks")
    op.drop_index("ix_remote_probes_zone", table_name="remote_probes")
    op.drop_index("ix_remote_probes_status", table_name="remote_probes")
    op.drop_table("remote_probes")
