# CS432-Assignment 4 (SafeDocs Sharded)

SafeDocs Flask application updated for Assignment 4 with 3-way sharding and shard-aware query routing.

## Overview

This repo implements horizontal partitioning for tenant data using:

- Shard key: `OrganizationID`
- Routing rule: `shard_index = OrganizationID % 3`
- 3 MySQL shard endpoints (ports `3307`, `3308`, `3309`)

Core/session/shared lookup data is handled through shard 0, while tenant/project tables are distributed across all shards.

## Architecture

### Sharded tables

Per shard, tenant tables use prefixes like `shard0_*`, `shard1_*`, `shard2_*`:

- users
- documents
- permissions
- logs
- versions
- passwords
- userpasswords
- docpasswords
- document_tags

### Coordinator and shared tables (shard 0)

- `CoreUsers`
- `CoreSessions`
- `CoreMemberLinks`
- `CoreGroupMemberships`
- `CoreAuditLogs`
- `CoreAuditState`
- `Organizations`
- `Roles`
- `Policies`
- `Tags`

## Repository Structure

- [app.py](app.py): app entrypoint
- [__init__.py](__init__.py): app factory and bootstrap
- [config.py](config.py): environment and shard config
- [database.py](database.py): shard engines/sessions/routing helpers
- [auth.py](auth.py): auth/session handling
- [routes.py](routes.py): APIs and pages
- [models.py](models.py): core ORM models
- [audit.py](audit.py): audit logging utilities
- [sql](sql): SQL scripts
- [templates](templates): UI templates
- [splitting.md](splitting.md): data splitting queries used for migration

## Configuration

1. Copy [.env.example](.env.example) to `.env`.
2. Set team DB credentials and shard endpoints.

Important variables:

- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `DB_NAME`
- `SHARD_COUNT`
- `SHARD_0_PORT`
- `SHARD_1_PORT`
- `SHARD_2_PORT`
- `FLASK_SECRET_KEY`
- `JWT_SECRET`

## Run Locally

```powershell
python -m pip install -r requirements.txt
python -m app
```

Open: `http://127.0.0.1:5000/login`

## Shard Routing Notes

- Organization-scoped operations route to one shard using `OrganizationID`.
- Global/admin listing paths can fan out to all shards and merge results in the app layer.
- Shared lookup values (org/role/tag/policy names) are loaded from shard 0 and reused.

## Data Migration

Splitting SQL used to move original tables into shard-prefixed tables is documented in [splitting.md](splitting.md).





