# App (Flask + RBAC + Indexing)

This module implements a local Flask web app and API layer for SafeDocs, with:

- Session-authenticated APIs
- Admin vs Regular RBAC
- Member portfolio UI
- CRUD APIs for project tables (Documents)
- Permission grant/revoke APIs
- Security audit logging (table + local file)
- SQL indexing scripts and EXPLAIN profiling hooks

## Project Layout

- `app.py`: app entry point
- `__init__.py`: app factory + bootstrap
- `routes.py`: UI/API routes
- `auth.py`: auth/session validation decorators
- `models.py`: core module tables + password tables (`UserPasswords`, `DocPasswords`)
- `database.py`: DB session and bootstrap helpers
- `audit.py`: audit file + table logging helpers
- `templates/`: UI templates
- `sql/create_core_tables.sql`: core table DDL
- `sql/indexes.sql`: indexing strategy DDL
- `logs/audit.log`: local audit file

## Environment

Copy the values from `.env.example` into your local `.env` (root or module path), then set:

- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `FLASK_SECRET_KEY`
- `JWT_SECRET`
- `DEFAULT_ADMIN_USERNAME`
- `DEFAULT_ADMIN_PASSWORD`

## Install

From repository root:

```powershell
venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run

From repository root:

```powershell
python app.py
```

Open:

- `http://127.0.0.1:5000/login` (UI login)
- `http://127.0.0.1:5000/` (welcome API)

## Required Auth APIs

- `GET /api/health`: returns service health and DB availability status.
- `POST /login`
  - JSON: `{"user": "...", "password": "..."}`
- `GET /isAuth`
  - Header: `Authorization: Bearer <session_token>`
- `GET /`

## Additional APIs

- `POST /api/members`
- `DELETE /api/members/<core_user_id>`
- `GET /api/documents`
- `GET /api/documents/<doc_id>`
- `POST /api/documents`
  - If `IsPasswordProtected` is true, include `DocumentPassword` in payload.
- `PUT /api/documents/<doc_id>`
- `DELETE /api/documents/<doc_id>`
- `POST /api/permissions/grant`
- `POST /api/permissions/revoke`
- `GET /api/audit/logs`
- `GET /api/audit/unauthorized`
- `GET /api/optimization/explain/documents`

## Additional UI Pages

- `GET /members`: member list page (regular users can browse members in their organization).
- `GET /documents`: table of accessible documents with per-row "View" action.
- `GET/POST /documents/<doc_id>/view`: password-gated document viewer page (prompts for password if protected).

## Document Access Behavior

- Regular users can list/open only documents they own or have explicit permission for (`View`, `Edit`, `Delete`).
- Document updates are allowed for users with owner/edit access.
- Protected documents require password entry in the viewer page before opening.

## SQL Optimization Workflow

1. Capture baseline query profile using the app benchmark tooling.
2. Apply indexes from `sql/indexes.sql`
3. Rerun benchmark and compare:
   - `average_ms`
   - EXPLAIN output

## Notes

- If MySQL is down, the app starts in degraded mode and DB-backed endpoints return a DB unavailable response.
- Project-specific tables from Task 1 are expected in the same database (for example: `Users`, `Documents`, `Permissions`, `Logs`).
- Project user logins are validated through `UserPasswords` when available; Core admin login remains supported.
