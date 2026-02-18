# SOC Sentinel AI Agent Cluster

A multi-agent security alert triage system built with [LangGraph](https://github.com/langchain-ai/langgraph) and powered by [K2 Think V2](https://k2think.ai/) reasoning model.

SOC Sentinel processes batches of security alerts through a team of specialised AI agents that triage, enrich, investigate, and cross-verify findings before producing a final briefing for human analysts.

## Architecture

```
                         +-------------+
                         |  Commander  |
                         +------+------+
                                |
               +----------------+----------------+
               |                |                |
        +------+------+  +-----+-------+  +-----+-------+
        |   Triage    |  |   Threat    |  |  Forensics  |
        |   Officer   |  |   Hunter    |  |   Analyst   |
        +------+------+  +-----+-------+  +-----+-------+
               |                |                |
               +----------------+----------------+
                                |
                       +--------+--------+
                       | Oversight       |
                       | Officer (K2)    |
                       +--------+--------+
                                |
                    confidence < 70?
                     /              \
                   yes               no
                    |                 |
              [loop back]     +------+------+
              to Commander    |   Briefing  |
              (max 3x)       |   Writer    |
                             +-------------+
```

**Commander** routes alerts to all three specialists in parallel via LangGraph's `Send`.

**Triage Officer** classifies alert severity (Critical/High/Medium/Low/Noise) using AbuseIPDB and GreyNoise IP reputation data.

**Threat Hunter** enriches IOCs (IPs, domains, hashes) using AlienVault OTX and VirusTotal. Detects APT/nation-state indicators from OTX pulse names and maps alert types to MITRE ATT&CK techniques.

**Forensics Analyst** reconstructs kill chains and queries NIST NVD for related CVEs when APT activity is suspected.

**Oversight Officer** (powered by K2 Think V2) cross-verifies ALL agent findings. Detects severity conflicts, hallucinated CVE IDs, invalid MITRE technique IDs, and kill chain contradictions. Assigns a confidence score (0-100) and overrides severity when Triage underestimates threats flagged by Threat Hunter.

**Briefing Writer** produces a final human-readable report with severity breakdown, verdict, and assessment.

### Re-Investigation Loop

If the Oversight Officer's confidence score falls below 70 and fewer than 3 iterations have run, the graph loops back to the Commander for re-investigation. This ensures uncertain findings get a second (or third) look.

## Security APIs

| API | Purpose | Required |
|-----|---------|----------|
| [AbuseIPDB](https://abuseipdb.com/) | IP reputation scoring | Yes |
| [AlienVault OTX](https://otx.alienvault.com/) | Threat intelligence pulses | Yes |
| [VirusTotal](https://www.virustotal.com/) | Malware/IP analysis | Yes |
| [NIST NVD](https://nvd.nist.gov/) | CVE lookups with CVSS scores | Yes |
| [GreyNoise](https://www.greynoise.io/) | IP noise/benign classification | Optional (stubs gracefully) |
| [IPinfo](https://ipinfo.io/) | IP geolocation | Optional (not yet integrated) |

No auth required for: MITRE ATT&CK mappings (built-in), ThreatMiner, URLhaus, ThreatFox.

## LLM

[K2 Think V2](https://k2think.ai/) (`MBZUAI-IFM/K2-Think-v2`) via OpenAI-compatible API. The model produces `<think>...</think>` reasoning blocks that are extracted and preserved for audit/debugging. Currently powers the Oversight Officer; other agents use rule-based logic with API data.

## Project Structure

```
.
+-- apis/                    # Security API clients
|   +-- abuseipdb.py         # IP reputation (confidence 0-100)
|   +-- greynoise.py         # IP classification (graceful stub)
|   +-- nvd.py               # NVD CVE search with CVSS extraction
|   +-- otx.py               # OTX pulse lookups (IP + domain)
|   +-- virustotal.py        # VT v3 analysis (IP + domain)
+-- graph/                   # LangGraph agent system
|   +-- graph.py             # StateGraph wiring + compilation
|   +-- nodes.py             # Agent node implementations
|   +-- prompts.py           # K2 Think system prompts
|   +-- run.py               # Test runner with mock alerts
|   +-- state.py             # SOCState TypedDict schema
|   +-- utils.py             # extract_reasoning() parser
+-- testAPI/                 # K2 Think API validation scripts
|   +-- test_k2_basic.py     # Verify API responds + reasoning tags
|   +-- test_k2_tools.py     # Confirm tool calling unsupported
|   +-- test_k2_reasoning.py # Test reasoning extraction parser
+-- .env                     # API keys (not committed)
+-- .gitignore
```

## Setup

### Prerequisites

- Python 3.11+
- API keys for K2 Think, AbuseIPDB, OTX, VirusTotal, NVD

### Installation

```bash
git clone https://github.com/j-sauer-devs/soc-sentinel-ai-agent-cluster.git
cd soc-sentinel-ai-agent-cluster
python3 -m venv venv
source venv/bin/activate
pip install langgraph langchain-core langchain-openai openai streamlit requests python-dotenv
```

### Configuration

Create a `.env` file in the project root:

```
K2_API_KEY=your_k2_key
ABUSEIPDB_KEY=your_key
OTX_KEY=your_key
VIRUSTOTAL_KEY=your_key
NVD_KEY=your_key
GREYNOISE_KEY=          # optional
IPINFO_KEY=             # optional
```

### Verify K2 Think API

```bash
python3 testAPI/test_k2_basic.py
python3 testAPI/test_k2_tools.py
python3 testAPI/test_k2_reasoning.py
```

### Run the Full Pipeline

```bash
python3 -m graph.run
```

## Example Output

```
------------------------------------------------------------------------------------------------------------------------
Alert ID     Source IP           AbuseIPDB  OTX Pulses  VT Malicious     Triage Threat Actor               CVEs
------------------------------------------------------------------------------------------------------------------------
ALERT-001    45.33.32.156                0           3             3     Medium Unknown                       0
ALERT-002    8.8.8.8                     0           0             0       High Unknown                       0
ALERT-003    10.0.0.88                   0          -1             0     Medium Unknown                       3
------------------------------------------------------------------------------------------------------------------------

Oversight Verdict : THREAT
Confidence Score  : 62.0/100
Severity Override : Critical
Conflicts Flagged : 2
  [ALERT-001] SEVERITY_CONFLICT: Triage=Medium but Threat Hunter found APT suspicion -> overridden to Critical
  [ALERT-002] KILL_CHAIN_CONTRADICTION: Forensics kill chain contradicts DNS Query Anomaly classification
APT Indicators    : 45.33.32.156 (associated with APT29 Cozy Bear C2)
```

## Key Design Decisions

**Parallel fan-out with append-only state** - Triage, Threat Hunter, and Forensics run concurrently. LangGraph's `Annotated[list, operator.add]` fields merge results from parallel branches without conflicts.

**K2 Think reasoning extraction** - The model sometimes omits the opening `<think>` tag during streaming. The parser (`graph/utils.py`) handles both complete `<think>...</think>` blocks and the `...</think>` fallback.

**Shared API caches** - Module-level dictionaries prevent duplicate API calls during re-investigation loops. Each IP/domain is queried once per run regardless of iteration count.

**Graceful degradation** - Missing API keys return stub responses instead of crashing. GreyNoise returns `{"classification": "unknown", "noise": false}` when its key is absent.

## Roadmap

- [ ] Wire K2 Think into Triage Officer for LLM-based severity classification
- [ ] Wire K2 Think into Threat Hunter for enriched IOC analysis
- [ ] Wire K2 Think into Forensics Analyst for kill chain reasoning
- [ ] Add Streamlit UI with Reasoning Inspector panel
- [ ] Add persistent alert history storage
- [ ] Integrate GreyNoise and IPinfo APIs
- [ ] Add real-time alert ingestion (webhook/SIEM integration)

## License

MIT
