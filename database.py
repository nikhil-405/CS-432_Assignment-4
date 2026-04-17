from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from werkzeug.security import generate_password_hash

from config import Config
from models import Base, CoreAuditLog, CoreAuditState, CoreGroupMembership, CoreMemberLink, CoreSession, CoreUser

SHARD_COUNT = Config.SHARD_COUNT
TENANT_TABLES = [
    "Users",
    "Documents",
    "Permissions",
    "Logs",
    "Versions",
    "Passwords",
    "UserPasswords",
    "DocPasswords",
    "Document_Tags",
]
SHARED_LOOKUP_TABLES = [
    "Organizations",
    "Roles",
    "Policies",
    "Tags",
]
CORE_TABLES = [
    CoreUser.__table__,
    CoreSession.__table__,
    CoreMemberLink.__table__,
    CoreGroupMembership.__table__,
    CoreAuditLog.__table__,
    CoreAuditState.__table__,
]

_ENGINE_CACHE: dict[int, Engine] = {}
_SESSION_FACTORY_CACHE: dict[int, scoped_session] = {}


def shard_index_for_organization(organization_id: int) -> int:
    return int(organization_id) % SHARD_COUNT


def tenant_table_name(base_name: str, shard_index: int) -> str:
    return f"shard{shard_index}_{base_name.lower()}"


def get_engine(shard_index: int = 0) -> Engine:
    if shard_index not in _ENGINE_CACHE:
        _ENGINE_CACHE[shard_index] = create_engine(
            Config.database_url(port=Config.shard_port(shard_index)),
            pool_pre_ping=True,
            future=True,
        )
    return _ENGINE_CACHE[shard_index]


def get_session(shard_index: int = 0) -> Session:
    if shard_index not in _SESSION_FACTORY_CACHE:
        _SESSION_FACTORY_CACHE[shard_index] = scoped_session(
            sessionmaker(bind=get_engine(shard_index), autoflush=False, autocommit=False, future=True)
        )
    return _SESSION_FACTORY_CACHE[shard_index]()


def get_core_session() -> Session:
    return get_session(0)


def get_project_session(organization_id: int) -> Session:
    return get_session(shard_index_for_organization(organization_id))


def get_shard_session(shard_index: int) -> Session:
    return get_session(shard_index)


def get_shard_indices() -> range:
    return range(SHARD_COUNT)


def _query_mappings(session: Session, statement: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return session.execute(text(statement), parameters or {}).mappings().all()


def _query_first(session: Session, statement: str, parameters: dict[str, Any] | None = None) -> dict[str, Any] | None:
    row = session.execute(text(statement), parameters or {}).mappings().first()
    return dict(row) if row is not None else None


def _fetch_project_row_by_id(base_table: str, id_column: str, identifier: int, shard_index: int | None = None) -> tuple[dict[str, Any] | None, int | None]:
    shard_indices = [shard_index] if shard_index is not None else list(get_shard_indices())
    for index in shard_indices:
        session = get_shard_session(index)
        row = _query_first(
            session,
            f"SELECT * FROM `{tenant_table_name(base_table, index)}` WHERE `{id_column}` = :identifier",
            {"identifier": identifier},
        )
        if row is not None:
            return row, index
    return None, None


def fetch_project_user(user_id: int, shard_index: int | None = None) -> tuple[dict[str, Any] | None, int | None]:
    return _fetch_project_row_by_id("Users", "UserID", user_id, shard_index)


def fetch_project_document(doc_id: int, shard_index: int | None = None) -> tuple[dict[str, Any] | None, int | None]:
    return _fetch_project_row_by_id("Documents", "DocID", doc_id, shard_index)


def fetch_project_permission(permission_id: int, shard_index: int | None = None) -> tuple[dict[str, Any] | None, int | None]:
    return _fetch_project_row_by_id("Permissions", "PermissionID", permission_id, shard_index)


def fetch_project_document_password(doc_id: int, shard_index: int | None = None) -> tuple[dict[str, Any] | None, int | None]:
    return _fetch_project_row_by_id("DocPasswords", "DocID", doc_id, shard_index)


@lru_cache(maxsize=1)
def load_reference_maps() -> dict[str, dict[int, str]]:
    session = get_core_session()
    try:
        organizations = {
            int(row["OrganizationID"]): str(row["OrgName"])
            for row in _query_mappings(session, "SELECT `OrganizationID`, `OrgName` FROM `Organizations`")
        }
    except SQLAlchemyError:
        organizations = {}

    try:
        roles = {
            int(row["RoleID"]): str(row["RoleName"])
            for row in _query_mappings(session, "SELECT `RoleID`, `RoleName` FROM `Roles`")
        }
    except SQLAlchemyError:
        roles = {}

    try:
        policies = {
            int(row["PolicyID"]): str(row.get("PolicyName") or row.get("Name") or row.get("Policy"))
            for row in _query_mappings(session, "SELECT * FROM `Policies`")
            if row.get("PolicyID") is not None
        }
    except SQLAlchemyError:
        policies = {}

    try:
        tags = {
            int(row["TagID"]): str(row.get("TagName") or row.get("Name") or row.get("Tag"))
            for row in _query_mappings(session, "SELECT * FROM `Tags`")
            if row.get("TagID") is not None
        }
    except SQLAlchemyError:
        tags = {}

    return {
        "organizations": organizations,
        "roles": roles,
        "policies": policies,
        "tags": tags,
    }


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_core_schema() -> None:
    engine = get_engine(0)
    Base.metadata.create_all(bind=engine, tables=CORE_TABLES)

    with session_scope() as session:
        tracking_key = "tracking_started_at"
        state = session.get(CoreAuditState, tracking_key)
        if state is None:
            state = CoreAuditState(
                state_key=tracking_key,
                state_value=datetime.now(timezone.utc).isoformat(),
            )
            session.add(state)


def seed_default_admin() -> None:
    with session_scope() as session:
        admin = (
            session.query(CoreUser)
            .filter(CoreUser.username == Config.DEFAULT_ADMIN_USERNAME)
            .one_or_none()
        )
        if admin is None:
            session.add(
                CoreUser(
                    username=Config.DEFAULT_ADMIN_USERNAME,
                    password_hash=generate_password_hash(Config.DEFAULT_ADMIN_PASSWORD),
                    role="Admin",
                    is_active=True,
                )
            )


def get_missing_project_tables() -> list[str]:
    try:
        missing: list[str] = []

        core_existing = {name.lower() for name in inspect(get_engine(0)).get_table_names()}
        for table in (table.name for table in CORE_TABLES):
            if table.lower() not in core_existing:
                missing.append(f"shard0:{table}")

        for shard_index in get_shard_indices():
            existing = {name.lower() for name in inspect(get_engine(shard_index)).get_table_names()}
            expected = [tenant_table_name(table, shard_index) for table in TENANT_TABLES]
            for table_name in expected:
                if table_name.lower() not in existing:
                    missing.append(f"shard{shard_index}:{table_name}")

        shard0_existing = {name.lower() for name in inspect(get_engine(0)).get_table_names()}
        for table in SHARED_LOOKUP_TABLES:
            if table.lower() not in shard0_existing:
                missing.append(f"shard0:{table}")

        return missing
    except SQLAlchemyError:
        return [f"shard0:{table.name}" for table in CORE_TABLES] + [
            f"shard{shard_index}:{tenant_table_name(table, shard_index)}"
            for shard_index in get_shard_indices()
            for table in TENANT_TABLES
        ] + [f"shard0:{table}" for table in SHARED_LOOKUP_TABLES]


def next_numeric_id(session: Session, table_name: str, id_column: str) -> int:
    query = text(f"SELECT COALESCE(MAX(`{id_column}`), 0) + 1 AS next_id FROM `{table_name}`")
    result = session.execute(query).scalar_one()
    return int(result)


def run_sql_script(script_path: str) -> None:
    with open(script_path, "r", encoding="utf-8") as handle:
        script = handle.read()

    statements = [part.strip() for part in script.split(";") if part.strip()]
    with get_engine().begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
