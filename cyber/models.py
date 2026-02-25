from pydantic import BaseModel
from typing import List, Optional, Any


class CyberQuery(BaseModel):
    user_id: str
    threat_type: str
    description: str


class CyberResponse(BaseModel):
    risk_level: str
    risk_score: int
    threat_name: str
    category: str
    mitigation: str
    recommendation: str
    indicators: List[str]
    affected_systems: List[str]
    cve_references: List[str]
    analysis_time_seconds: float
    confidence_score: int
    miner_nodes_consulted: int
    validator_nodes_consulted: int
    miner_responses: List[dict]
    validator_results: List[dict]
    tao_reward_pool: float
    consensus_reached: bool
    block_number: int
    timestamp: str
    subnet_version: str
