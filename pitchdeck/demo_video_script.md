# AI Cybersecurity Network Demo Video Script

**Duration:** 5-7 minutes

---

## Scene 1: Opening (0:00-0:30)
- [Visual] Project logo with cybersecurity theme (dark background, neon green/blue accents). Animated shield icon.
- [Voice Over] "Welcome to AI Cybersecurity Network Subnet - the decentralized threat intelligence platform powered by Bittensor. In a world where cyber threats cost over $10 trillion a year, we're building the open, incentivized defense network the internet needs."

## Scene 2: The Problem (0:30-1:00)
- [Visual] News headlines about data breaches, ransomware attacks. Animated data silos with lock icons. Statistics overlay.
- [Voice Over] "Cyber threats evolve faster than any single team can track. Security data is siloed across organizations. Small businesses and Web3 projects are left vulnerable because enterprise-grade threat intelligence is expensive and centralized."

## Scene 3: The Solution (1:00-1:45)
- [Visual] Animated network of nodes sharing threat data. Bittensor logo integrating with security nodes. $TAO token flowing between nodes.
- [Voice Over] "Our solution: a Bittensor subnet where security experts and AI models collaborate in real-time. Miners detect and analyze threats. Validators verify accuracy against trusted databases like CVE and MITRE ATT&CK. Quality contributions earn $TAO rewards. All activity is transparent and on-chain."

## Scene 4: Mechanism Design Deep Dive (1:45-3:00)
- [Visual] Animated diagram showing the full flow:
  1. User submits threat query
  2. Multiple miners analyze
  3. Validators cross-reference
  4. Scores computed
  5. Rewards distributed
- [Voice Over] "Here's how the mechanism works. A user submits a threat query - an IP address, a suspicious URL, or a log pattern. Multiple miners analyze the threat independently, returning risk levels and mitigation strategies. Validators then verify these analyses against known threat databases. Each miner gets a quality score based on accuracy, speed, and detail. $TAO rewards flow to the best contributors."
- [Visual] Show scoring formula: `Score = 0.6 * Accuracy + 0.3 * Speed + 0.1 * Detail`

## Scene 5: Live Demo (3:00-5:00)
- [Visual] Screen recording:
  1. Terminal: `uvicorn main:app --reload`
  2. Open browser/Postman: POST to `/analyze`
  3. Show JSON request: `{"threat_type": "phishing", "description": "Suspicious email with link to fake banking site"}`
  4. Show JSON response with risk_level, mitigation, recommendations
  5. (Optional) Show Bittensor node dashboard or subnet metrics
- [Voice Over] "Let's see it in action. We start our API server, submit a phishing threat query to the /analyze endpoint, and within seconds receive a detailed risk assessment with mitigation strategies. In a production subnet, this query would be processed by multiple miners and validated for accuracy."

## Scene 6: Go-to-Market & Impact (5:00-6:00)
- [Visual] GTM roadmap timeline. Partner logos (Web3 projects, DeFi protocols). Market size stats.
- [Voice Over] "Our go-to-market starts with Web3 and DeFi projects - a natural fit for decentralized security. We'll expand to enterprise SIEM integrations and eventually build an open marketplace for custom threat detection models. The cybersecurity market is $223 billion and growing."

## Scene 7: Closing & Call to Action (6:00-7:00)
- [Visual] Team info, social links, project logo. "Join Us" call to action.
- [Voice Over] "AI Cybersecurity Network Subnet - making enterprise-grade threat intelligence open, decentralized, and accessible to everyone. Join us in building the future of cybersecurity on Bittensor."

---
**Production Tips:**
- Use dark theme throughout (black/dark gray with neon green and blue accents).
- Screen recordings should use a dark terminal theme.
- Background music: subtle electronic/tech ambient.
- Voice should be confident and clear, moderate pace.
