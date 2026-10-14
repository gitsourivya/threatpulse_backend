
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import SQLModel, Field


def current_timestamp():
    return datetime.now(timezone.utc).isoformat()


class NetworkEventRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    source_ip: str
    destination_ip: str

    source_port: int
    destination_port: int

    protocol: str
    timestamp: str

    received_at: str = Field(default_factory=current_timestamp)


class AlertRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    source_ip: str
    severity: str
    reason: str

    risk_score: int = Field(default=0)
    risk_reasons: str = Field(default="")

    event_id: Optional[int] = Field(
        default=None,
        foreign_key="networkeventrecord.id"
    )

    created_at: str = Field(default_factory=current_timestamp)
