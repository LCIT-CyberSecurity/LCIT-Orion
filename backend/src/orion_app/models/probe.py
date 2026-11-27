"""Inventory and durable observations for centrally managed remote probes."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from orion_app.database import Base, JsonType


class RemoteProbe(Base):
    __tablename__ = "remote_probes"
    __table_args__ = (
        UniqueConstraint("address", "api_port", name="uq_remote_probe_address_port"),
        Index("ix_remote_probes_zone", "network_zone_id"),
        CheckConstraint(
            "status IN ('pairing', 'active', 'disabled', 'revoked')",
            name="ck_remote_probe_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120))
    address: Mapped[str] = mapped_column(String(45))
    api_port: Mapped[int] = mapped_column(Integer, default=9443)
    network_zone_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("network_zones.id", ondelete="RESTRICT")
    )
    certificate_sha256: Mapped[str] = mapped_column(String(64))
    certificate_pem: Mapped[str] = mapped_column(Text)
    encrypted_token: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="pairing", index=True)
    capabilities: Mapped[list] = mapped_column(JsonType, default=list)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_cursor: Mapped[int] = mapped_column(Integer, default=0)
    pending_ack_cursor: Mapped[int | None] = mapped_column(Integer)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RemoteProbeTask(Base):
    __tablename__ = "remote_probe_tasks"
    __table_args__ = (
        Index("ix_remote_probe_tasks_probe_status", "probe_id", "status"),
        CheckConstraint(
            "kind IN ('tls', 'ssh', 'ipsec', 'dns')", name="ck_remote_probe_task_kind"
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted')",
            name="ck_remote_probe_task_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    probe_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("remote_probes.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(String(12))
    request_payload: Mapped[dict] = mapped_column(JsonType)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    error: Mapped[str] = mapped_column(String(80), default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RemoteProbeEvent(Base):
    __tablename__ = "remote_probe_events"
    __table_args__ = (
        UniqueConstraint("probe_id", "event_id", name="uq_remote_probe_event_id"),
        UniqueConstraint("probe_id", "cursor", name="uq_remote_probe_event_cursor"),
        Index("ix_remote_probe_events_received", "received_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    probe_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("remote_probes.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[str] = mapped_column(String(36))
    cursor: Mapped[int] = mapped_column(Integer)
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("remote_probe_tasks.id", ondelete="SET NULL")
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    payload: Mapped[dict] = mapped_column(JsonType)
