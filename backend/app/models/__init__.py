"""Re-exports all ORM models so `from app.models import *` and Alembic's
autogenerate both see the full metadata without hunting through submodules."""

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.investigation import Investigation
from app.models.user import User

__all__ = ["Alert", "Asset", "Investigation", "User"]
