from fastapi import APIRouter
from .models import CyberQuery, CyberResponse
from .ai import get_cybersecurity_advice

router = APIRouter()

@router.post("/analyze")
def analyze(query: CyberQuery):
    result = get_cybersecurity_advice(query)
    return CyberResponse(**result)
