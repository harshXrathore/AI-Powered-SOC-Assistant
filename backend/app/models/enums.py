"""
Shared enums for roles, severities, and status fields.

Purpose:
    Single definition of every fixed-choice field so models, schemas, and
    business logic all reference the same values — avoids the classic bug
    where the DB accepts "Critical" but the API validates "critical".
"""

import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"


class AssetCriticality(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertSeverity(str, enum.Enum):
    """
    Maps from Wazuh's 1-15 numeric rule level into four buckets used
    throughout the API and dashboard. See utils/severity.py for the
    numeric-to-bucket mapping function.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"


class InvestigationStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
