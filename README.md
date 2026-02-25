# AI Cybersecurity Network Subnet

**Subnet #10 — Bittensor Ideathon**

A decentralized real-time threat intelligence platform on Bittensor. Miners compete to detect and analyze cyber threats using AI models trained on global threat feeds. Validators verify detection accuracy against known threat databases. Rewards ($TAO) are distributed via Yuma Consensus.

## Quick Start (For Judges)

```bash
# 1. Clone & enter directory
git clone https://github.com/yt2025id-lab/bittensor-cybersecurity.git
cd bittensor-cybersecurity

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
uvicorn main:app --reload --port 8000

# 4. Open in browser
open http://localhost:8000
```

### What You'll See

- **Interactive Web UI** at `http://localhost:8000` — click any of the 3 demo scenarios
- **Swagger API Docs** at `http://localhost:8000/docs` — test all endpoints interactively
- **ReDoc** at `http://localhost:8000/redoc` — clean API reference

### Demo Scenarios

| # | Scenario | Task Type |
|---|----------|-----------|
| 1 | DeFi smart contract vulnerability scan | Threat Detection |
| 2 | Phishing campaign analysis — credential harvesting | Threat Intelligence |
| 3 | Network anomaly — possible C2 beacon detection | Anomaly Detection |

Each demo broadcasts a cybersecurity challenge to 6 simulated miners, scores their detection through 3-4 validators, and distributes TAO rewards via Yuma Consensus.

## Features

- 6 specialized security AI miners (ThreatHunter, MalwareNet, AnomalyDetector, etc.)
- 3-4 validators with threat database verification pipelines
- Vulnerability scanning, threat intelligence, anomaly detection
- Real-time scoring: true positive rate, detection speed, false positive penalty
- TAO reward distribution via Yuma Consensus
- Full miner/validator CRUD, leaderboard, and network status APIs

## Folder Structure

```
main.py                  # FastAPI entry point
cyber/
  __init__.py
  ai.py                  # AI threat analysis engine (3 demo scenarios, 6 miners)
  db.py                  # In-memory DB (miners, validators, challenges)
  models.py              # Pydantic data models
  routes.py              # 20+ API endpoints
static/
  index.html             # Interactive demo UI
  app.js                 # Frontend logic
  style.css              # Dark theme styling
overview.md              # Full technical documentation
pitchdeck/               # Pitch deck materials
SUBNET_PROPOSAL.md       # Detailed subnet design proposal
```

## Scoring Formula

```
final_score = (0.40 × detection_accuracy + 0.25 × classification_quality
             + 0.15 × speed + 0.10 × false_positive_penalty + 0.10 × consistency)
             × 1.5 if zero-day threat correctly identified
```

## Subnet Parameters

- **Subnet ID:** 10 | **Tempo:** 360 blocks (~72 min) | **Max UIDs:** 256
- **Emission Split:** Owner 18% | Miners 41% | Validators+Stakers 41%

## Miner Tasks

| Task | Weight | Description |
|------|--------|-------------|
| Threat Detection | 50% | Real-time malware, exploit, and vulnerability detection |
| Threat Intelligence | 30% | Threat actor profiling and campaign analysis |
| Anomaly Detection | 20% | Network and behavioral anomaly identification |

## License

MIT

## Documentation

- [`SUBNET_PROPOSAL.md`](SUBNET_PROPOSAL.md) — Full technical subnet design proposal
- [`overview.md`](overview.md) — Problem/solution, architecture, mechanism design
- [`pitchdeck/`](pitchdeck/) — Pitch deck and demo video script
