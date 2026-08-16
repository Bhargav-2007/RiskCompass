# Dynamic Vulnerability Intelligence & Risk Scoring Platform - System Architecture

## Overview
This platform shifts vulnerability prioritization from static CVSS scores to an AI/ML-powered contextual model that calculates the true probability of exploitation within a specific organizational environment.

## Core Modules & Interactions

### 1. Vulnerability Ingestion Module
- **Responsibilities**: 
  - Pull CVE data from NVD/NVD APIs
  - Fetch EPSS scores from FIRST.org
  - Check CISA KEV catalog
  - Collect CWE, exploit availability (Exploit-DB, Metasploit), publication dates
  - Normalize and store in PostgreSQL
- **Inputs**: NVD API, EPSS API, CISA KEV JSON, Exploit-DB APIs
- **Outputs**: Standardized vulnerability records in `vulnerabilities` table
- **Innovations Integrated**:
  - Real-Time Threat Context: Enriches vulnerabilities with threat velocity scores from MISP/dark web feeds
  - Community-Driven Risk Intelligence: Receives anonymized risk signals via federated learning APIs

### 2. Asset Context Engine
- **Responsibilities**:
  - Maintain CMDB of organizational assets (servers, APIs, cloud resources)
  - Track asset attributes: internet exposure, data sensitivity, business importance, ownership
  - Map vulnerabilities to affected assets via CPE matching and custom tags
  - Calculate asset criticality scores
- **Inputs**: CMDB (via API/manual import), network scanners, cloud asset inventories (AWS/Azure/GCP)
- **Outputs**: Asset-vulnerability mappings in `asset_vulnerabilities` table, asset criticality scores
- **Innovations Integrated**:
  - Business Impact Quantification: Ties asset attributes to financial impact using FAIR factors
  - Automated Attack Path Simulation: Uses asset relationships to build attack graphs
  - Edge Computing Scoring: Provides lightweight asset context to edge nodes

### 3. AI/ML Risk Engine
- **Responsibilities**:
  - Train and serve XGBoost/LightGBM models for dynamic risk scoring
  - Feature engineering from vulnerability, asset, threat, and temporal data
  - Model versioning and A/B testing
  - SHAP value calculation for explainability
- **Inputs**: 
  - Vulnerability features (CVSS, EPSS, KEV, age, etc.)
  - Asset features (criticality, exposure, sensitivity)
  - Threat features (threat velocity, exploit availability, threat actor activity)
  - Temporal features (time since publication, EPSS momentum)
- **Outputs**: Risk scores (0-100), feature importance, SHAP explanations
- **Innovations Integrated**:
  - Predictive Exploitability Modeling: Outputs feed as features to predict 30/60/90-day exploitation
  - AI-Powered False Positive Reduction: Anomaly detection flags low-risk vulns for auto-closure
  - Dynamic Industry Risk Thresholds: Adjusts model weights per industry profile
  - Natural Language Explainable AI: LLMs convert SHAP values to narratives

### 4. Dynamic Scoring Engine
- **Responsibilities**:
  - Combine ML risk scores with business rules and policy
  - Generate final risk score (0-100) and prioritization tier (P0-P3)
  - Apply attack path adjustments (increase score if on path to crown jewels)
  - Trigger recalculations on data changes
- **Inputs**: 
  - ML risk scores from AI/ML Risk Engine
  - Attack path probabilities from simulation engine
  - Business impact quantification
  - Industry-specific thresholds
- **Outputs**: Final risk score, priority tier, score rationale
- **Innovations Integrated**:
  - Automated Attack Path Simulation: Adjusts scores based on breach chain probability
  - Business Impact Quantification: Modifies scores by potential financial loss
  - Dynamic Industry Risk Thresholds: Applies industry-specific risk appetite

### 5. Risk Analytics Dashboard
- **Responsibilities**:
  - Visualize risk distributions (P0/P1/P2/P3)
  - Compare model performance (CVSS-only vs CVSS+EPSS vs Dynamic Risk)
  - Show highest-risk assets and vulnerability trends
  - Display patch backlog and remediation velocity
- **Inputs**: 
  - Risk scores from Dynamic Scoring Engine
  - Asset criticality and business impact data
  - Remediation ticketing system (Jira/ServiceNow)
- **Outputs**: Interactive charts, tables, and reports
- **Innovations Integrated**:
  - Gamified Risk Awareness: Displays team/individual risk reduction points and leaderboards
  - Automated Remediation Playbooks: Links to LLM-generated remediation steps

### 6. Continuous Reprioritization System
- **Responsibilities**:
  - Monitor data sources for changes (EPSS updates, new KEV, threat feeds)
  - Trigger asynchronous recalculation of affected vulnerability scores
  - Update dashboards and alert security teams of priority changes
- **Inputs**: 
  - Webhooks from EPSS, CISA KEV, threat intelligence platforms
  - Asset change notifications from CMDB/scanners
  - Scheduled cron jobs for time-based features (vulnerability age)
- **Outputs**: Updated risk scores, priority changes, alert notifications
- **Innovations Integrated**:
  - Real-Time Threat Context: Immediate rescoring on threat velocity spikes
  - Predictive Exploitability Modeling: Updates as EPSS momentum changes
  - Adversary Emulation: Incorporates new exploitation data from honeypots

### Supporting Systems
- **Automated Remediation Playbooks**: LLM-generated workflows integrated with SOAR (via webhooks)
- **Adversary Emulation**: Honeypot deployment system feeding exploitation data back to ML engine
- **Community-Driven Risk Intelligence**: Federated learning coordinator with differential privacy
- **Edge Computing Scoring**: Dockerized lightweight models deployed to Kubernetes edge nodes
- **DevSecOps Integration**: GitHub Action that calls risk API to block PRs with P0/P1 vulns
- **Natural Language Explainable AI**: Slack bot that delivers risk narratives on demand
- **Automated Patch Testing**: Chaos engineering integration for pre-deployment validation
- **Blockchain Auditability**: Hyperledger Fabric chaincode storing immutable risk score logs

## Data Flow
1. Vulnerability Ingestion pulls CVE/EPSS/KEV data → PostgreSQL
2. Asset Context Engine enriches with asset data → Asset-Vulnerability mappings
3. AI/ML Risk Engine trains on historical exploitation data → Risk model
4. Dynamic Scoring Engine combines ML scores with context → Final risk score & tier
5. Continuous Reprioritization monitors triggers → Async score updates
6. Risk Analytics Dashboard consumes scored data → Visualizations
7. Innovations feed into various modules as described above

## Technology Stack
- **Backend**: Python 3.9+, FastAPI, PostgreSQL, Redis, Celery
- **AI/ML**: scikit-learn, XGBoost, LightGBM, pandas, numpy, SHAP, Prophet/LSTM
- **Frontend**: React 18, TypeScript, Tailwind CSS, Recharts
- **Intelligence Feeds**: NVD, EPSS, CISA KEV, CWE, Exploit-DB, MISP, Dark web APIs
- **Security**: JWT/OAuth2, RBAC, TLS encryption, AWS KMS for key management
- **Deployment**: Docker, Docker-compose, Kubernetes (for edge), GitHub Actions
- **Monitoring**: Prometheus, Grafana, ELK stack