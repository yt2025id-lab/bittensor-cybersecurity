# Project 10: AI Cybersecurity Network Subnet

## Overview
A decentralized, real-time threat intelligence and cybersecurity analytics platform powered by Bittensor. Security experts and AI models collaborate to detect, analyze, and mitigate cyber threats with on-chain transparency and token incentives.

## Features
- Real-time AI-driven threat analysis
- Decentralized threat intelligence sharing
- Risk assessment and mitigation strategies
- SIEM integration support
- Bittensor subnet integration with $TAO rewards

## Getting Started
1. Install dependencies: `pip install -r requirements.txt`
2. Run the app: `python main.py`
3. Submit threat queries via `/analyze` endpoint

## Folder Structure
- `main.py`: Entry point (FastAPI)
- `cyber/`: Core logic
  - `ai.py`: AI threat analysis engine
  - `models.py`: Data models (CyberQuery, CyberResponse)
  - `routes.py`: API routes
  - `db.py`: Database operations
- `overview.md`: Full project documentation
- `pitchdeck/`: Presentation materials
- `requirements.txt`: Dependencies

## Bittensor Subnet Design
- **Miner:** Detects and analyzes cyber threats, generates threat reports and risk scores
- **Validator:** Verifies detection accuracy against known threat databases, scores true positive rate
- **Incentive:** $TAO rewards based on detection accuracy and response speed

## License
MIT

## Full Documentation
See `overview.md` for detailed problem/solution, architecture, and mechanism design.
See `pitchdeck/` for pitch deck, demo video script, and visual guide.
