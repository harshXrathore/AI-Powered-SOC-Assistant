-- Runs automatically on first container start (docker-entrypoint-initdb.d).
-- Extensions required by later phases:
--   uuid-ossp   -> UUID primary keys for alerts/users/reports
--   pg_trgm     -> fuzzy text search over alert descriptions / IOC values
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
