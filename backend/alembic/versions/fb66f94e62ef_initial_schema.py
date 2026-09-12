"""initial schema — users, assets, alerts, investigations

Revision ID: fb66f94e62ef
Revises:
Create Date: 2026-07-05 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "fb66f94e62ef"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

user_role = postgresql.ENUM("admin", "analyst", "readonly", name="user_role")
asset_criticality = postgresql.ENUM("critical", "high", "medium", "low", name="asset_criticality")
alert_severity = postgresql.ENUM("critical", "high", "medium", "low", name="alert_severity")
alert_status = postgresql.ENUM(
    "new", "in_progress", "resolved", "false_positive", "ignored", name="alert_status"
)
investigation_status = postgresql.ENUM(
    "open", "in_progress", "closed", name="investigation_status"
)


def upgrade() -> None:
    bind = op.get_bind()
    user_role.create(bind, checkfirst=True)
    asset_criticality.create(bind, checkfirst=True)
    alert_severity.create(bind, checkfirst=True)
    alert_status.create(bind, checkfirst=True)
    investigation_status.create(bind, checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", user_role, nullable=False, server_default="readonly"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("operating_system", sa.String(255), nullable=True),
        sa.Column(
            "criticality", asset_criticality, nullable=False, server_default="medium"
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("hostname"),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("wazuh_alert_id", sa.String(128), nullable=False),
        sa.Column("rule_id", sa.String(32), nullable=False),
        sa.Column("rule_description", sa.String(512), nullable=False),
        sa.Column("severity", alert_severity, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("agent_name", sa.String(255), nullable=True),
        sa.Column("log_message", sa.Text(), nullable=True),
        sa.Column("raw_event", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", alert_status, nullable=False, server_default="new"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("wazuh_alert_id"),
    )
    op.create_index("ix_alerts_wazuh_alert_id", "alerts", ["wazuh_alert_id"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index("ix_alerts_source_ip", "alerts", ["source_ip"])
    op.create_index("ix_alerts_destination_ip", "alerts", ["destination_ip"])
    op.create_index("ix_alerts_agent_name", "alerts", ["agent_name"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_severity_timestamp", "alerts", ["severity", "timestamp"])
    op.create_index("ix_alerts_status_timestamp", "alerts", ["status", "timestamp"])

    op.create_table(
        "investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("analyst_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "status", investigation_status, nullable=False, server_default="open"
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["analyst_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_investigations_alert_id", "investigations", ["alert_id"])
    op.create_index("ix_investigations_analyst_id", "investigations", ["analyst_id"])


def downgrade() -> None:
    op.drop_table("investigations")
    op.drop_table("alerts")
    op.drop_table("assets")
    op.drop_table("users")

    bind = op.get_bind()
    investigation_status.drop(bind, checkfirst=True)
    alert_status.drop(bind, checkfirst=True)
    alert_severity.drop(bind, checkfirst=True)
    asset_criticality.drop(bind, checkfirst=True)
    user_role.drop(bind, checkfirst=True)
