"""Service layer for operator settings and custom detection patterns."""

from .service import (
    DEFAULT_RETENTION_DAYS,
    DEFAULT_WORKSPACE_NAME,
    SettingsFailure,
    enabled_custom_patterns,
    read_settings,
    update_settings,
)

__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "DEFAULT_WORKSPACE_NAME",
    "SettingsFailure",
    "enabled_custom_patterns",
    "read_settings",
    "update_settings",
]
