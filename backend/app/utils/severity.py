"""
Wazuh rule-level to AlertSeverity mapping.

Purpose:
    Wazuh rules carry a numeric "level" from 0-15. This project buckets
    that into four severities used consistently across the DB, API, and
    dashboard. Thresholds follow Wazuh's own documented convention for
    what constitutes a security-relevant vs. informational event.

Mapping:
    12-15 -> critical
    8-11  -> high
    4-7   -> medium
    0-3   -> low
"""

from app.models.enums import AlertSeverity


def severity_from_level(level: int) -> AlertSeverity:
    if level >= 12:
        return AlertSeverity.CRITICAL
    if level >= 8:
        return AlertSeverity.HIGH
    if level >= 4:
        return AlertSeverity.MEDIUM
    return AlertSeverity.LOW
