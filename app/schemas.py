
from pydantic import BaseModel, Field


class NetworkEvent(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    protocol: str
    timestamp: str
