from fastapi import APIRouter
from typing import List
from .models import CyberQuery, CyberResponse
from .ai import get_cybersecurity_advice, get_dashboard_stats, get_live_feed

router = APIRouter()


@router.post("/api/analyze", response_model=CyberResponse)
def analyze(query: CyberQuery):
    result = get_cybersecurity_advice(query)
    return CyberResponse(**result)


@router.get("/api/dashboard")
def dashboard():
    return get_dashboard_stats()


@router.get("/api/live-feed")
def live_feed():
    return get_live_feed(count=6)


@router.get("/api/threat-types")
def threat_types():
    return [
        {"value": "malware", "label": "Malware / Ransomware", "icon": "bug"},
        {"value": "phishing", "label": "Phishing / Social Engineering", "icon": "mail"},
        {"value": "ddos", "label": "DDoS Attack", "icon": "zap"},
        {"value": "sql injection", "label": "SQL Injection / Web Attack", "icon": "code"},
        {"value": "zero-day", "label": "Zero-Day Exploit", "icon": "alert-triangle"},
        {"value": "insider threat", "label": "Insider Threat", "icon": "user-x"},
    ]
