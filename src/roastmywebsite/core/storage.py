from __future__ import annotations

from pathlib import Path

from sqlalchemy import Column, DateTime, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session

from ..config import DB_PATH
from .models import ScanResult


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    mode = Column(String, nullable=False)
    started_at = Column(DateTime, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    data = Column(Text, nullable=False)


_engine = None


def get_engine(db_path: Path = DB_PATH):
    global _engine
    if _engine is None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{db_path}", future=True)
        Base.metadata.create_all(_engine)
    return _engine


def save_scan(result: ScanResult) -> None:
    engine = get_engine()
    with Session(engine) as session:
        row = session.get(ScanRow, result.id)
        payload = result.model_dump_json()
        if row is None:
            row = ScanRow(
                id=result.id,
                target=result.target,
                mode=result.mode,
                started_at=result.started_at,
                finished_at=result.finished_at,
                data=payload,
            )
            session.add(row)
        else:
            row.target = result.target
            row.mode = result.mode
            row.started_at = result.started_at
            row.finished_at = result.finished_at
            row.data = payload
        session.commit()


def list_scans(limit: int = 50) -> list[dict]:
    engine = get_engine()
    with Session(engine) as session:
        rows = session.query(ScanRow).order_by(ScanRow.started_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "target": r.target,
                "mode": r.mode,
                "started_at": r.started_at.isoformat(),
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            }
            for r in rows
        ]


def get_scan(scan_id: str) -> ScanResult | None:
    engine = get_engine()
    with Session(engine) as session:
        row = session.get(ScanRow, scan_id)
        if row is None:
            return None
        return ScanResult.model_validate_json(row.data)


def delete_old_scans(keep: int = 100) -> None:
    engine = get_engine()
    with Session(engine) as session:
        rows = session.query(ScanRow).order_by(ScanRow.started_at.desc()).offset(keep).all()
        for row in rows:
            session.delete(row)
        session.commit()