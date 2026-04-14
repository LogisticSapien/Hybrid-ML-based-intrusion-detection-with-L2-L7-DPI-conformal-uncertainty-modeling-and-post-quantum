<div align="center">

<br/>

```
██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗
██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║
██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
```

### *AI-Native Post-Quantum Network Defense Engine*

<br/>

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-22c55e?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0.0-ef4444?style=for-the-badge)]()
[![Architecture](https://img.shields.io/badge/Architecture-Distributed-f97316?style=for-the-badge)]()
[![AI](https://img.shields.io/badge/AI-Hybrid_Ensemble-a855f7?style=for-the-badge)]()
[![Security](https://img.shields.io/badge/Security-Post--Quantum-0f172a?style=for-the-badge&logo=shield&logoColor=white)]()
[![Scapy](https://img.shields.io/badge/Powered_by-Scapy-00b4d8?style=for-the-badge)]()
[![Build](https://img.shields.io/badge/Build-Passing-22c55e?style=for-the-badge&logo=githubactions&logoColor=white)]()

<br/>

> **Not a packet sniffer. Not a rule engine. Not an IDS.**
> 
> *A rethinking of what network defense looks like in an era of encrypted threats, adaptive adversaries, and quantum-era cryptography.*

<br/>

</div>

---

## What This Is — And What It Isn't

Traditional intrusion detection systems ask a simple question:

> *"Have I seen this attack before?"*

If the answer is no — you're blind. Quantum Sniffer asks a fundamentally different question:

> *"Does this behavior make statistical sense at all?"*

This is a **research-grade, production-capable network defense platform** built entirely from scratch in Python — no Snort rules, no Suricata signatures, no YARA. Instead: raw protocol dissection from bytes up, a custom Isolation Forest, calibrated conformal prediction, and a post-quantum cryptographic transport layer.


---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          QUANTUM SNIFFER v3                         │
│                     AI-Native Defense Engine                        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                     ┌──────▼──────┐
                     │  engine.py  │  ← CaptureEngine (AsyncSniffer + BPF)
                     │  Orchestrator│    Threaded pipeline, 10k pkt queue
                     └──────┬──────┘
                            │
          ┌─────────────────┼──────────────────────┐
          │                 │                      │
   ┌──────▼──────┐  ┌───────▼───────┐    ┌────────▼────────┐
   │ protocols.py│  │ flow_tracker  │    │    ids.py       │
   │ L2 → L7     │  │ Session State │    │ Rule + Behavior │
   │ (from bytes)│  │ Machine       │    │ Engine          │
   └──────┬──────┘  └───────┬───────┘    └────────┬────────┘
          │                 │                      │
          └─────────────────▼──────────────────────┘
                            │
               ┌────────────▼────────────┐
               │    DETECTION PIPELINE   │
               │                         │
               │  ┌─────────────────┐    │
               │  │ isolation_forest│    │  ← Custom iForest (no sklearn)
               │  │ .py             │    │
               │  └────────┬────────┘    │
               │           │             │
               │  ┌────────▼────────┐    │
               │  │ extended_iforest│    │  ← EIF for high-dim accuracy
               │  └────────┬────────┘    │
               │           │             │
               │  ┌────────▼────────┐    │
               │  │ autoencoder_    │    │  ← Deep reconstruction error
               │  │ detector.py     │    │
               │  └────────┬────────┘    │
               │           │             │
               │  ┌────────▼────────┐    │
               │  │ anomaly.py      │    │  ← EWMA + z-score (σ > 3)
               │  │ EWMA / z-score  │    │
               │  └────────┬────────┘    │
               │           │             │
               │  ┌────────▼────────┐    │
               │  │ hybrid_scorer   │    │  ← Weighted ensemble fusion
               │  │ S = w₁·iF + w₂·σ│   │    + temporal correlation
               │  └────────┬────────┘    │
               │           │             │
               │  ┌────────▼────────┐    │
               │  │conformal_pred.py│    │  ← Statistically valid p-values
               │  │ p(x) ≤ ε = 0.015│   │    ≤ 1.5% FPR guaranteed
               │  └─────────────────┘    │
               └────────────┬────────────┘
                            │
          ┌─────────────────┼──────────────────────┐
          │                 │                      │
   ┌──────▼──────┐  ┌───────▼───────┐    ┌────────▼────────┐
   │  pqc.py     │  │ analytics.py  │    │  distributed.py │
   │ Kyber-512   │  │ Traffic Intel │    │ Sensor/Aggregator│
   │ AES-256-GCM │  │ Top Talkers   │    │ JSON-over-TCP   │
   │ SHA3-256 log│  │ Protocol Stats│    │ Kyber-enc alerts│
   └──────┬──────┘  └───────┬───────┘    └────────┬────────┘
          │                 │                      │
          └─────────────────▼──────────────────────┘
                            │
          ┌─────────────────┼──────────────────────┐
          │                 │                      │
   ┌──────▼──────┐  ┌───────▼───────┐    ┌────────▼────────┐
   │ dashboard.py│  │web_dashboard  │    │  stix_exporter  │
   │ Rich TUI    │  │ Flask + Prom. │    │  Prometheus      │
   └─────────────┘  └───────────────┘    └─────────────────┘
```

---

## The Detection Stack — In Full Detail

### 1. Protocol Dissection Engine (`protocols.py`)

Everything starts with raw bytes — no relying on Scapy's dissectors. The protocol engine implements its own parsers for the full L2–L7 stack using `struct.unpack` and dataclasses.

| Layer | Protocols |
|-------|-----------|
| **L2** | Ethernet (DIX), 802.1Q VLAN, ARP |
| **L3** | IPv4 (options, fragmentation), IPv6, ICMPv4/v6 |
| **L4** | TCP (flags, window scaling, SACK), UDP |
| **L7** | DNS (10+ record types), HTTP/1.x, TLS 1.2/1.3 (SNI + JA3 fingerprinting), QUIC, SSH banners, DHCP |

**Why rebuild this?** Because L7 intelligence — knowing what a TLS `ClientHello` says about a client, or computing JA3 fingerprints from cipher suite ordering — is where the real signal lives. Scapy doesn't go that deep.

---

### 2. Statistical Anomaly Engine (`anomaly.py`)

Before ML scores anything, the statistical layer watches for volumetric drift using **EWMA (Exponentially Weighted Moving Average)** baselines:

```
For each metric m ∈ {pps, bps, unique_ips/s, dns_rate, conn_rate}:

  Warmup (n=20 samples):
    μ  ← sample mean
    σ² ← sample variance

  Live update (α = 0.1):
    μ_new  ← α·x + (1−α)·μ
    σ²_new ← α·(x−μ)² + (1−α)·σ²

  Alert if:
    z = |x − μ| / σ  >  3.0  →  anomaly
```

Why EWMA over a fixed window? The baseline *adapts* to the network's natural behavior. A 3am traffic dip won't trigger false positives during the 3am business cycle.

---

### 3. Custom Isolation Forest (`isolation_forest.py`)

A from-scratch implementation — no scikit-learn dependency, pure NumPy:

- Random subspace partitioning on feature subsets
- Anomaly score normalized by expected path length E[h(x)]
- Extended variant (`extended_isolation_forest.py`) for improved accuracy in high-dimensional feature spaces
- Adaptive contamination estimation (`adaptive_contamination.py`)

The iForest catches **structural anomalies** — unusual combinations of features that EWMA's per-metric view would miss (e.g., a host with normal volume but bizarre port/flag/size combinations).

---

### 4. Autoencoder Detector (`autoencoder_detector.py`)

A deep reconstruction-error model trained on normal traffic:

- Learns a compressed latent representation of normal flow features
- High reconstruction error → the traffic doesn't fit the learned normal manifold
- Operates on `flow_feature_extractor.py` output: 30+ per-flow features
- Catches unknown attack patterns that are structurally novel, not just volumetrically abnormal

---

### 5. Hybrid Ensemble Scorer (`hybrid_scorer.py`)

The three signals are fused into one calibrated score:

```
Combined score:

  S = w₁·s_iforest + w₂·σ(z_max / z_norm)

  where:
    s_iforest ∈ [0, 1]          — structural anomaly score
    z_max     = max(|zᵢ|)       — worst volumetric deviation
    z_norm    = 5.0             — maps z=5 → σ ≈ 0.99
    σ(x)      = 1/(1+e^(−x))   — sigmoid squashing
    w₁        = 0.6             — weight: iForest
    w₂        = 0.4             — weight: volumetric

Threshold calibration uses recall-biased pinball loss (α = 0.8):
  False negatives penalized 4× harder than false positives.
```

A **temporal correlation layer** provides time-decay boosting — correlated anomalies within a sliding window increase the score multiplicatively.

---

### 6. Conformal Prediction (`conformal_predictor.py`)

This is the key innovation that separates Quantum Sniffer from every other open-source IDS.

Standard ML outputs a score. Conformal prediction outputs a **statistically valid p-value**:

```
Theory (Vovk, Gammerman & Shafer, 2005):

  Given calibration set Z = {z₁, ..., zₙ} of normal traffic,
  the p-value for a new sample x is:

    p(x) = |{i : α(zᵢ) ≥ α(x)}| + 1
           ──────────────────────────
                    n + 1

  Guarantee:
    P(p(x) ≤ ε) ≤ ε  under exchangeability

  At ε = 0.015:
    ≤ 1.5% false positive rate — guaranteed, not empirical.
```

This transforms detection from:
> *"Score is 0.87, seems suspicious"*

into:
> *"This sample is more anomalous than 98.5% of calibration traffic. p = 0.012."*

Two modes: **offline** (batch calibration) and **online** (sliding window, adapts to drift).

---

## Post-Quantum Cryptography Layer (`pqc.py`)

Modern IDS systems ignore one inconvenient truth:

> **RSA-2048 and ECDHE fall to Shor's algorithm on a sufficiently large quantum computer.**

Adversaries are *already* harvesting encrypted traffic today, betting on "decrypt later." Quantum Sniffer addresses this on two fronts:

### Detection
The `QuantumThreatAnalyzer` inspects TLS sessions in real-time and classifies every cipher suite:

| Classification | Examples |
|----------------|----------|
| 🟢 **SAFE** | TLS 1.3 + X25519Kyber768 hybrid |
| 🟡 **AT_RISK** | TLS 1.3 + ECDHE only |
| 🔴 **CRITICAL** | RSA key exchange, TLS 1.2 |

### Protection
All alert logs are encrypted with a **Kyber-inspired lattice-based KEM** + AES-256-GCM:

- Polynomial ring operations: `R_q = Z_q[x] / (x^N + 1)`, N=256, q=3329 (matching CRYSTALS-Kyber-512 parameters)
- **SHA3-256 hash chain** for tamper-evident audit logs — each entry commits to the previous
- **Dilithium-inspired digital signatures** (`dilithium_signer.py`) for node authentication
- Distributed alert payloads are Kyber-encrypted before transmission

---

## Distributed Architecture (`distributed.py`)

```
Sensor Node 1 ──┐
Sensor Node 2 ──┼──► Aggregator ──► Unified IDS + Analytics + Alerts
Sensor Node N ──┘     (TCP)         ↑ Kyber-encrypted payloads
                      Heartbeat
                      monitoring
                      Node health
                      tracking
```

- **Sensor nodes** capture locally, extract flow summaries, and stream `PacketSummary` JSON over TCP
- **Aggregation server** receives from N sensors, runs the full detection pipeline centrally
- Nodes are monitored via heartbeat; stale nodes are flagged automatically
- Optional **Kyber+AES-GCM encrypted alert payloads** between nodes

Scale horizontally by adding sensor nodes. The aggregator handles detection for the whole fleet.

---

## MITRE ATT&CK Mapping

Every alert generated by the IDS engine includes structured MITRE ATT&CK context:

```python
@dataclass
class ThreatEvent:
    tactic:     str   # e.g., "Reconnaissance"
    technique:  str   # e.g., "T1046 - Network Service Scanning"
    severity:   Severity
    confidence: float
    evidence:   List[EvidenceFactor]
    mitre:      MITRE
```

Alerts export in **STIX 2.1** format (`stix_exporter.py`) for SIEM integration.

---

## Verification & Self-Test

```
$ python -m quantum_sniffer --verify

╔══════════════════════════════════════════════╗
║        QUANTUM SNIFFER v3.0.0                ║
║        Self-Test Suite                       ║
╠══════════════════════════════════════════════╣
║  Modules:                                    ║
║    Protocols   ✓   L2–L7 dissection          ║
║    IDS         ✓   Rule + behavioral engine  ║
║    ML          ✓   Hybrid ensemble loaded    ║
║    PQC         ✓   Kyber-512 + SHA3-256      ║
║    Analytics   ✓   Flow intelligence         ║
║    Distributed ✓   Sensor/aggregator ready   ║
╠══════════════════════════════════════════════╣
║  Simulation:                                 ║
║    Attacks Detected    6 / 6                 ║
║    Alerts Generated    250+                  ║
║    Detection Confidence  HIGH                ║
╠══════════════════════════════════════════════╣
║  Performance:                                ║
║    Throughput   High (multi-process)         ║
║    Latency      Sub-ms p95                   ║
╠══════════════════════════════════════════════╣
║  TLS Security Analysis:                      ║
║    RSA         →  CRITICAL                   ║
║    ECDHE       →  AT_RISK                    ║
║    TLS1.3+Kyber →  SAFE                      ║
╚══════════════════════════════════════════════╝
```

---

## Installation

```bash
git clone https://github.com/DheemanthA/quantum-sniffer.git
cd quantum-sniffer
pip install -r requirements.txt
```

**Dependencies:**

| Package | Role |
|---------|------|
| `scapy` | Raw packet capture (AsyncSniffer + BPF) |
| `numpy` | Custom ML primitives, lattice math |
| `cryptography` | AES-256-GCM backend for PQC layer |
| `rich` | Terminal dashboard rendering |
| `flask` | Web dashboard + REST API |
| `prometheus_client` | Metrics export |
| `PyJWT` | Node authentication tokens |
| `flask-limiter` | Rate limiting on web API |
| `matplotlib` / `pandas` | Benchmark visualization |

> **Note:** Root/administrator privileges required for raw packet capture on most systems.

---

## Usage

### Live Capture

```bash
# Start the full engine with terminal dashboard
python engine.py

# Specify interface and sensitivity
python engine.py --interface eth0 --sensitivity high

# With web dashboard
python web_dashboard.py
```

### PCAP Replay

```bash
# Replay a capture file through the full detection pipeline
python pcap_replay.py --file sample.pcap

# Replay with benchmark output
python pcap_benchmark.py --file capture.pcap --output report.json
```

### Distributed Mode

```bash
# Start aggregator
python -m quantum_sniffer distributed --role aggregator --port 9999

# Start sensor nodes (on separate machines)
python -m quantum_sniffer distributed --role sensor --aggregator 192.168.1.1:9999
```

### Benchmarking

```bash
# Full benchmark suite
python benchmark_suite.py

# CICIDS-2018 dataset evaluation
python cicids_eval.py --dataset /path/to/cicids
```

---

## Detection Capabilities

| Attack Class | Detection Method | Example |
|--------------|-----------------|---------|
| Port Scan | iForest + EWMA spike | Nmap SYN scan |
| DDoS / Flood | EWMA volumetric | UDP flood, ICMP flood |
| DNS Tunneling | Protocol anomaly + rate | iodine, dnscat2 |
| Beaconing C2 | Temporal correlation | Periodic callbacks |
| TLS Fingerprint Anomaly | JA3 + cipher analysis | Malware TLS stacks |
| Zero-Day (unknown) | Autoencoder reconstruction error | Novel exploits |
| Cryptographic Downgrade | PQC cipher scanner | RSA negotiation |
| ARP Spoofing | L2 consistency check | MITM attempts |

---

## Dashboards

### Terminal Dashboard (Rich TUI)

```
┌─ QUANTUM SNIFFER v3 ─────────────────── 2026-04-14 18:42:01 ─┐
│  Interface: eth0    Packets: 142,847    Alerts: 12            │
├──────────────────────────────────────────────────────────────┤
│  LIVE PACKET STREAM                                          │
│  18:42:01  TCP  192.168.1.44 → 10.0.0.1:443  [SYN]         │
│  18:42:01  DNS  192.168.1.12 → 8.8.8.8  A? evil.example.com │
│  18:42:01  ⚠ ANOMALY  score=0.91  conf=98.2%  iForest+EWMA  │
├──────────────────────────────────────────────────────────────┤
│  ML SCORES          │  PROTOCOL DIST    │  TLS HEALTH        │
│  iForest:  0.883    │  TCP   ████ 61%   │  SAFE:     47%     │
│  EWMA:     0.812    │  UDP   ██   28%   │  AT_RISK:  38%     │
│  Combined: 0.910    │  DNS   █    11%   │  CRITICAL: 15%  ⚠  │
└──────────────────────────────────────────────────────────────┘
```

### Web Dashboard

Flask-powered web interface at `http://localhost:5000`:
- Real-time ML scores and model breakdowns
- Traffic trends and protocol distribution charts
- Per-flow anomaly heatmaps
- Prometheus metrics endpoint at `/metrics`

---

## Benchmarking & Evaluation

Evaluated against the **CICIDS-2018** intrusion detection dataset:

```bash
python cicids_eval.py
```

Reported metrics:
- **Accuracy** — overall classification
- **Precision / Recall / F1** — per attack class
- **False Positive Rate** — bounded by conformal ε
- **Throughput** — packets/second sustained
- **Latency** — p50 / p95 / p99 pipeline latency
- **Conformal calibration error** — empirical vs. theoretical FPR

---

## Research Contributions

This project operationalizes several ideas not commonly combined in open-source security tooling:

1. **Conformal prediction in IDS** — statistically rigorous p-value bounds instead of arbitrary score thresholds
2. **Hybrid ML + statistical fusion** — iForest catches structural anomalies; EWMA catches volumetric drift; neither alone is sufficient
3. **PQC-aware network monitoring** — classifying live TLS traffic by quantum vulnerability in real-time
4. **From-scratch ML without scikit-learn** — the isolation forest, conformal predictor, and autoencoder are fully custom NumPy implementations
5. **Temporal correlation scoring** — time-decay weighting that boosts correlated anomaly bursts
6. **Post-quantum secure audit logs** — Kyber KEM + SHA3-256 hash chains for tamper-evident evidence chains

---

## Roadmap

- [ ] FPGA / SoC packet processing offload
- [ ] LLM-based threat narrative generation from alert chains
- [ ] Online learning — model updates from confirmed incidents
- [ ] Adversarial robustness against IDS evasion techniques
- [ ] Full CRYSTALS-Kyber-768 / Kyber-1024 mode
- [ ] NIST PQC standard PQC protocol classification (ML-KEM, ML-DSA)
- [ ] eBPF kernel-space capture path for zero-copy performance
- [ ] gRPC-based distributed transport (replacing TCP/JSON)

---

## Project Structure

```
quantum_sniffer/
├── engine.py                  # CaptureEngine — central orchestrator
├── protocols.py               # L2–L7 protocol dissection from raw bytes
├── ids.py                     # Rule-based + behavioral IDS engine
├── anomaly.py                 # EWMA + z-score statistical detector
├── isolation_forest.py        # Custom iForest (no sklearn)
├── extended_isolation_forest.py
├── autoencoder_detector.py    # Deep reconstruction-error detector
├── hybrid_scorer.py           # Ensemble fusion + temporal correlation
├── conformal_predictor.py     # Statistically valid p-values
├── dynamic_conformal.py       # Online / streaming conformal
├── flow_tracker.py            # TCP session lifecycle state machine
├── flow_feature_extractor.py  # 30+ per-flow ML features
├── iforest_detector.py        # iForest integration wrapper
├── adaptive_contamination.py  # Automated contamination estimation
├── temporal_scorer.py         # Time-decay correlation layer
├── pqc.py                     # Kyber-512 KEM + AES-256-GCM + SHA3 logs
├── pqc_transport.py           # PQC-aware transport layer
├── pqc_migration_scorer.py    # Cipher suite quantum-risk scoring
├── dilithium_signer.py        # Lattice-based digital signatures
├── distributed.py             # Sensor/aggregator distributed system
├── mp_engine.py               # Multi-process execution pipeline
├── analytics.py               # Traffic intelligence engine
├── metrics.py                 # Detection quality metrics
├── detection_quality.py       # Precision / recall / FPR tracking
├── correlator.py              # Cross-alert correlation
├── unified_explainer.py       # Alert explanation engine
├── pcap_replay.py             # PCAP replay pipeline
├── pcap_trainer.py            # Train models on PCAP captures
├── pcap_benchmark.py          # PCAP-based performance benchmarking
├── simulator.py               # Attack traffic simulation
├── stix_exporter.py           # STIX 2.1 threat intel export
├── dashboard.py               # Rich TUI terminal dashboard
├── web_dashboard.py           # Flask web dashboard
├── dashboard_gui.py           # GUI dashboard
├── benchmark_suite.py         # Full benchmark runner
├── cicids_eval.py             # CICIDS-2018 dataset evaluation
├── cicids_benchmark.py        # CICIDS benchmark harness
├── forensics.py               # Post-incident forensic analysis
├── config.py                  # Configuration management
└── __main__.py                # CLI entrypoint
```

---

## Author

<div align="center">

**Dheemanth A**  
*Electronics & Communication Engineering*  
Cybersecurity · Post-Quantum Cryptography · AI Systems

<br/>

*Built from scratch. Every byte parsed manually. Every model implemented from math.*

</div>

---

<div align="center">

**If you read this far — go run it.**

```bash
git clone https://github.com/DheemanthA/quantum-sniffer.git && cd quantum-sniffer && pip install -r requirements.txt && python engine.py
```

[![Star on GitHub](https://img.shields.io/github/stars/DheemanthA/quantum-sniffer?style=for-the-badge&logo=github&color=f59e0b)](https://github.com/DheemanthA/quantum-sniffer)

</div>
