from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import current_user, require_roles
from app.core.audit import record_event
from app.core.database import get_db
from app.core.security import encrypt_credential
from app.models import DatabaseConnection, SchemaSnapshot, User
from app.schemas.connections import (
    ConnectionCreate,
    ConnectionPage,
    ConnectionPatch,
    ConnectionResponse,
    ConnectionTestResponse,
    DiscoveryRequest,
    SnapshotResponse,
)
from app.services.discovery.catalog import (
    DiscoveryError,
    catalog_fingerprint,
    discover_catalog,
    validate_target_host,
)

router = APIRouter(prefix="/connections", tags=["Database connections"])


def find_connection(db: Session, connection_id: UUID, *, lock: bool = False) -> DatabaseConnection:
    query = select(DatabaseConnection).where(DatabaseConnection.id == connection_id)
    record = db.scalar(query.with_for_update() if lock else query)
    if record is None:
        raise HTTPException(404, "Database connection not found")
    return record


def validate_host(host: str) -> None:
    try:
        validate_target_host(host)
    except DiscoveryError as exc:
        raise HTTPException(exc.status_code, exc.message) from None


def commit_connection(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Connection name is already registered") from None


def snapshot_response(snapshot: SchemaSnapshot) -> SnapshotResponse:
    return SnapshotResponse(
        snapshot_id=snapshot.id,
        discovered_at=snapshot.created_at,
        fingerprint=snapshot.fingerprint,
        catalog=snapshot.catalog,
    )


def read_catalog(record: DatabaseConnection, payload: DiscoveryRequest | None) -> dict:
    if not record.is_active:
        raise HTTPException(409, "Reactivate this connection before testing or discovering")
    try:
        return discover_catalog(record, payload.schemas if payload else None)
    except DiscoveryError as exc:
        raise HTTPException(exc.status_code, exc.message) from None


@router.get("", response_model=ConnectionPage)
def list_connections(
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=20, ge=1, le=100),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> ConnectionPage:
    total = db.scalar(select(func.count()).select_from(DatabaseConnection)) or 0
    records = db.scalars(
        select(DatabaseConnection)
        .order_by(
            DatabaseConnection.created_at.desc(),
            DatabaseConnection.id.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return ConnectionPage(
        items=[ConnectionResponse.model_validate(item) for item in records],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=ConnectionResponse, status_code=201)
def create_connection(
    payload: ConnectionCreate,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> DatabaseConnection:
    validate_host(payload.host)
    values = payload.model_dump(exclude={"scanner_password", "deployer_password"})
    record = DatabaseConnection(
        **values,
        created_by=user.id,
        scanner_password_ciphertext=encrypt_credential(payload.scanner_password.get_secret_value()),
        deployer_password_ciphertext=(
            encrypt_credential(payload.deployer_password.get_secret_value())
            if payload.deployer_password
            else None
        ),
    )
    db.add(record)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Connection name is already registered") from None
    record_event(
        db,
        actor_id=user.id,
        event_type="CONNECTION_CREATED",
        subject_type="database_connection",
        subject_id=record.id,
    )
    commit_connection(db)
    return record


@router.patch("/{connection_id}", response_model=ConnectionResponse)
def update_connection(
    connection_id: UUID,
    payload: ConnectionPatch,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> DatabaseConnection:
    record = find_connection(db, connection_id, lock=True)
    fields = payload.model_fields_set
    if "host" in fields:
        validate_host(payload.host)
    if "scanner_username" in fields and payload.scanner_username != record.scanner_username:
        if "scanner_password" not in fields:
            raise HTTPException(422, "Changing the scanner username requires a new password")
    if "deployer_username" in fields and payload.deployer_username != record.deployer_username:
        if "deployer_password" not in fields:
            raise HTTPException(
                422, "Changing the deployment username requires a password decision"
            )
    deployer_username = (
        payload.deployer_username if "deployer_username" in fields else record.deployer_username
    )
    if "deployer_password" in fields:
        if (deployer_username is None) != (payload.deployer_password is None):
            raise HTTPException(422, "Supply or clear both deployment username and password")
        record.deployer_password_ciphertext = (
            encrypt_credential(payload.deployer_password.get_secret_value())
            if payload.deployer_password
            else None
        )
    for key, value in payload.model_dump(
        exclude_unset=True, exclude={"scanner_password", "deployer_password"}
    ).items():
        setattr(record, key, value)
    if payload.scanner_password:
        record.scanner_password_ciphertext = encrypt_credential(
            payload.scanner_password.get_secret_value()
        )
    record_event(
        db,
        actor_id=user.id,
        event_type="CONNECTION_UPDATED",
        subject_type="database_connection",
        subject_id=record.id,
    )
    commit_connection(db)
    return record


@router.post("/{connection_id}/test", response_model=ConnectionTestResponse)
def test_connection(
    connection_id: UUID,
    payload: DiscoveryRequest | None = None,
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
) -> ConnectionTestResponse:
    record = find_connection(db, connection_id, lock=True)
    catalog = read_catalog(record, payload)
    record_event(
        db,
        actor_id=user.id,
        event_type="CONNECTION_TESTED",
        subject_type="database_connection",
        subject_id=record.id,
    )
    db.commit()
    return ConnectionTestResponse(schemas=catalog["schemas"], table_count=len(catalog["tables"]))


@router.post("/{connection_id}/discover", response_model=SnapshotResponse)
def discover_connection(
    connection_id: UUID,
    payload: DiscoveryRequest | None = None,
    user: User = Depends(require_roles("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> SnapshotResponse:
    record = find_connection(db, connection_id, lock=True)
    catalog = read_catalog(record, payload)
    snapshot = SchemaSnapshot(
        connection_id=record.id, catalog=catalog, fingerprint=catalog_fingerprint(catalog)
    )
    db.add(snapshot)
    db.flush()
    record_event(
        db,
        actor_id=user.id,
        event_type="SCHEMA_DISCOVERED",
        subject_type="schema_snapshot",
        subject_id=snapshot.id,
    )
    db.commit()
    return snapshot_response(snapshot)


@router.get("/{connection_id}/schema", response_model=SnapshotResponse)
def connection_schema(
    connection_id: UUID,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> SnapshotResponse:
    find_connection(db, connection_id)
    snapshot = db.scalar(
        select(SchemaSnapshot)
        .where(
            SchemaSnapshot.connection_id == connection_id,
        )
        .order_by(SchemaSnapshot.created_at.desc(), SchemaSnapshot.id.desc())
        .limit(1)
    )
    if snapshot is None:
        raise HTTPException(404, "Discover this connection to create a schema snapshot")
    return snapshot_response(snapshot)
