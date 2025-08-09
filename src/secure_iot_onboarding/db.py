"""Database layer using SQLAlchemy ORM for devices & certificates."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    create_engine,
    Column,
    String,
    DateTime,
    Boolean,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session

DATABASE_URL = os.environ.get("DEVICE_DB_URL", "sqlite:///./data/devices.db")

engine = create_engine(DATABASE_URL, future=True, echo=False)
SessionLocal = scoped_session(
    sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False))
Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    location = Column(String, nullable=True)
    firmware = Column(String, nullable=True)
    registered_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="active")  # active | revoked

    certificate = relationship(
        "Certificate",
        back_populates="device",
        uselist=False,
        cascade="all, delete-orphan")
    __table_args__ = (UniqueConstraint("name", name="uq_device_name"),)


class Certificate(Base):
    __tablename__ = "certificates"
    device_id = Column(
        String,
        ForeignKey(
            "devices.id",
            ondelete="CASCADE"),
        primary_key=True)
    fingerprint = Column(String, nullable=False, unique=True)
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)

    device = relationship("Device", back_populates="certificate")


def init_db():
    Base.metadata.create_all(engine)


def add_device(
        name: str,
        type: str,
        location: Optional[str] = None,
        firmware: Optional[str] = None) -> Device:
    session = SessionLocal()
    device = Device(name=name, type=type, location=location, firmware=firmware)
    session.add(device)
    session.commit()
    session.refresh(device)
    session.close()
    return device


def add_certificate(
        device_id: str,
        fingerprint: str,
        expires_at) -> Certificate:
    session = SessionLocal()
    cert = Certificate(
        device_id=device_id,
        fingerprint=fingerprint,
        expires_at=expires_at)
    session.add(cert)
    session.commit()
    session.refresh(cert)
    session.close()
    return cert


def get_device(device_id: str) -> Optional[Device]:
    session = SessionLocal()
    device = session.get(Device, device_id)
    if device:
        # Eager load certificate before closing session
        _ = device.certificate
    session.expunge_all()
    session.close()
    return device


def revoke_device(device_id: str):
    session = SessionLocal()
    device = session.get(Device, device_id)
    if device:
        device.status = "revoked"
        if device.certificate:
            device.certificate.revoked = True
        session.commit()
    session.close()


__all__ = [
    "init_db",
    "add_device",
    "get_device",
    "revoke_device",
    "add_certificate",
    "Device",
    "Certificate",
]
