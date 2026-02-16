from pydantic import BaseModel

class CyberQuery(BaseModel):
    user_id: str
    threat_type: str
    description: str

class CyberResponse(BaseModel):
    risk_level: str
    mitigation: str
    recommendation: str
