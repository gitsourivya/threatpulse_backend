from app.classification import classify_event
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlmodel import Session, select

from app.database import create_db_and_tables, engine
from app.schemas import NetworkEvent
from app.detection import analyze_event
from app.risk_scoring import calculate_risk
from app.models import NetworkEventRecord, AlertRecord


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(
    title="Threat Pulse API",
    description="Real-time Network Threat Detection Backend",
    version="1.2.0",
    lifespan=lifespan,
)


@app.get("/")
def home():
    return {"message": "Threat Pulse API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/events")
def receive_event(event: NetworkEvent):
    data = event.model_dump()

    # Analyze the incoming network event.
    detection = analyze_event(data)
    classification = classify_event(data, detection)

    with Session(engine) as session:
        # Save the network event.
        event_record = NetworkEventRecord(**data)
        session.add(event_record)
        session.commit()
        session.refresh(event_record)

        saved_event_id = event_record.id

        # Determine the number of recent events for risk scoring.
        event_count = 1

        if detection["suspicious"]:
            try:
                event_count = int(detection["reason"].split()[0])
            except (ValueError, IndexError):
                event_count = 5

        # Calculate a demo risk score.
        risk = calculate_risk(
            event_count=event_count,
            suspicious=detection["suspicious"],
        )

        alert_data = None

        # Create and save an alert when suspicious activity is detected.
        if detection["suspicious"]:
            alert_record = AlertRecord(
                source_ip=event.source_ip,
                severity=risk["severity"],
                reason=detection["reason"],
                risk_score=risk["risk_score"],
                risk_reasons="; ".join(risk["reasons"]),
                event_id=saved_event_id,
            )

            session.add(alert_record)
            session.commit()
            session.refresh(alert_record)

            alert_data = {
                "id": alert_record.id,
                "source_ip": alert_record.source_ip,
                "severity": alert_record.severity,
                "reason": alert_record.reason,
                "risk_score": alert_record.risk_score,
                "risk_reasons": alert_record.risk_reasons,
                "event_id": alert_record.event_id,
                "created_at": alert_record.created_at,
            }

    return {
    "received": True,
    "event_id": saved_event_id,
    "detection": detection,
    "classification": classification,
    "risk": risk,
    "alert": alert_data,
}

@app.get("/events")
def get_events():
    with Session(engine) as session:
        statement = select(NetworkEventRecord).order_by(
            NetworkEventRecord.id.desc()
        )
        return session.exec(statement).all()


@app.get("/alerts")
def get_alerts():
    with Session(engine) as session:
        statement = select(AlertRecord).order_by(
            AlertRecord.id.desc()
        )
        return session.exec(statement).all()
