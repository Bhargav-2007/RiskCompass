-- Dynamic Vulnerability Intelligence & Risk Scoring Platform
-- PostgreSQL Database Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Vulnerabilities Table
-- Stores core vulnerability data from NVD, EPSS, KEV, etc.
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) UNIQUE NOT NULL,  -- e.g., CVE-2023-12345
    cvss_v3_score DECIMAL(3,1),          -- CVSS v3.1 base score (0.0-10.0)
    cvss_v3_vector VARCHAR(50),          -- CVSS v3.1 vector string
    cvss_v4_score DECIMAL(3,1),          -- CVSS v4.0 base score (if available)
    cvss_v4_vector VARCHAR(50),
    epss_score DECIMAL(5,4),             -- EPSS probability (0.0000-1.0000)
    epss_percentile DECIMAL(5,4),        -- EPSS percentile (0.0000-1.0000)
    kev BOOLEAN DEFAULT FALSE,           -- CISA Known Exploited Vulnerability
    kev_date DATE,                       -- Date added to KEV catalog
    cwe_id VARCHAR(10),                  -- e.g., CWE-79
    description TEXT,
    references JSONB,                    -- Array of reference URLs and tags
    exploit_available BOOLEAN DEFAULT FALSE, -- Public exploit exists (Exploit-DB, Metasploit)
    exploit_maturity VARCHAR(20),        -- e.g., 'proof-of-concept', 'functional', 'weaponized'
    published_date TIMESTAMP WITH TIME ZONE,
    modified_date TIMESTAMP WITH TIME ZONE,
    -- Additional fields for innovations
    threat_velocity_score DECIMAL(3,2),  -- Real-time threat context (0.00-1.00)
    exploit_prediction_30d DECIMAL(5,4), -- Predicted exploitation probability in 30 days
    exploit_prediction_60d DECIMAL(5,4), -- Predicted exploitation probability in 60 days
    exploit_prediction_90d DECIMAL(5,4), -- Predicted exploitation probability in 90 days
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for vulnerabilities
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_kev ON vulnerabilities(kev) WHERE kev = TRUE;
CREATE INDEX idx_vulnerabilities_epss_score ON vulnerabilities(epss_score);
CREATE INDEX idx_vulnerabilities_threat_velocity ON vulnerabilities(threat_velocity_score);

-- 2. Assets Table
-- Stores organizational assets (servers, APIs, cloud resources, etc.)
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_tag VARCHAR(100) UNIQUE,       -- Internal asset identifier
    hostname VARCHAR(255),
    ip_address INET,                     -- Supports IPv4 and IPv6
    mac_address MACADDR,
    asset_type VARCHAR(50),              -- e.g., 'server', 'web-app', 'database', 'cloud-storage'
    os VARCHAR(100),
    os_version VARCHAR(50),
    -- Asset context attributes
    internet_exposure BOOLEAN DEFAULT FALSE, -- Directly reachable from internet
    data_sensitivity VARCHAR(20),        -- e.g., 'public', 'internal', 'confidential', 'restricted'
    business_importance INTEGER,         -- 1-5 scale (5 = critical)
    asset_criticality_score DECIMAL(5,2),-- Computed criticality (0-100)
    owner_team VARCHAR(100),
    owner_email VARCHAR(255),
    -- Cloud-specific fields
    cloud_provider VARCHAR(20),          -- 'aws', 'azure', 'gcp', 'on-premise'
    cloud_region VARCHAR(50),
    cloud_instance_type VARCHAR(50),
    -- Tags for flexible categorization
    tags JSONB DEFAULT '{}'::jsonb,
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_scanned TIMESTAMP WITH TIME ZONE
);

-- Indexes for assets
CREATE INDEX idx_assets_internet_exposure ON assets(internet_exposure) WHERE internet_exposure = TRUE;
CREATE INDEX idx_assets_business_importance ON assets(business_importance);
CREATE INDEX idx_assets_asset_type ON assets(asset_type);
CREATE INDEX idx_assets_cloud_provider ON assets(cloud_provider);

-- 3. Asset-Vulnerability Mapping (Many-to-Many)
-- Links vulnerabilities to affected assets with instance-specific context
CREATE TABLE asset_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    -- Instance-specific vulnerability state
    status VARCHAR(20) DEFAULT 'open',   -- 'open', 'patched', 'mitigated', 'false-positive', 'risk-accepted'
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    patched_at TIMESTAMP WITH TIME ZONE,
    -- Override fields for asset-specific context
    asset_specific_cvss DECIMAL(3,1),    -- Adjusted CVSS based on asset config (e.g., auth required)
    exploitability_adjustment DECIMAL(3,2), -- Asset-specific exploitability modifier (0.0-1.0)
    -- Attack path context
    on_attack_path_to_crown_jewel BOOLEAN DEFAULT FALSE,
    attack_path_probability DECIMAL(5,4),-- Probability this vuln is on path to critical asset
    -- Business impact override
    asset_specific_business_impact DECIMAL(10,2), -- Financial impact if exploited on this asset
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(asset_id, vulnerability_id)
);

-- Indexes for asset_vulnerabilities
CREATE INDEX idx_asset_vulnerabilities_asset_id ON asset_vulnerabilities(asset_id);
CREATE INDEX idx_asset_vulnerabilities_vulnerability_id ON asset_vulnerabilities(vulnerability_id);
CREATE INDEX idx_asset_vulnerabilities_status ON asset_vulnerabilities(status);
CREATE INDEX idx_asset_vulnerabilities_attack_path ON asset_vulnerabilities(on_attack_path_to_crown_jewel) WHERE on_attack_path_to_crown_jewel = TRUE;

-- 4. Threat Intelligence Table
-- Stores enriched threat data from feeds, dark web, MISP, etc.
CREATE TABLE threat_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    -- Threat feeds
    source VARCHAR(100),                 -- e.g., 'MISP', 'AlienVault OTX', 'Darkweb Feed'
    threat_type VARCHAR(50),             -- e.g., 'malware', 'exploit-kit', 'ransomware', 'apt'
    threat_actor VARCHAR(100),           -- Attributed threat actor or group
    campaign VARCHAR(100),               -- Associated campaign name
    -- Dark web / chatter metrics
    dark_web_mentions INTEGER DEFAULT 0,
    dark_web_sentiment DECIMAL(3,2),     -- -1.0 (negative) to 1.0 (positive) sentiment
    exploit_code_available BOOLEAN DEFAULT FALSE,
    exploit_code_url TEXT,
    -- Temporal threat activity
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    activity_score DECIMAL(3,2),         -- Normalized activity level (0.00-1.00)
    -- Additional context
    references JSONB,                    -- URLs to threat reports, IOCs
    confidence DECIMAL(3,2),             -- Confidence in threat intelligence (0.00-1.00)
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for threat_intelligence
CREATE INDEX idx_threat_intelligence_vulnerability_id ON threat_intelligence(vulnerability_id);
CREATE INDEX idx_threat_intelligence_source ON threat_intelligence(source);
CREATE INDEX idx_threat_intelligence_threat_type ON threat_intelligence(threat_type);
CREATE INDEX idx_threat_intelligence_activity_score ON threat_intelligence(activity_score);

-- 5. Risk Scores Table
-- Stores the dynamic risk scores and prioritization tiers
CREATE TABLE risk_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_vulnerability_id UUID NOT NULL REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
    -- Core scoring components (0-100 scale)
    cvss_base_score DECIMAL(5,2),        -- CVSS score normalized to 0-100
    epss_component DECIMAL(5,2),         -- EPSS contribution to risk
    kev_component DECIMAL(5,2),          -- KEV bonus
    asset_criticality_component DECIMAL(5,2), -- Asset criticality contribution
    exposure_component DECIMAL(5,2),     -- Internet exposure contribution
    exploit_availability_component DECIMAL(5,2), -- Exploit availability contribution
    threat_activity_component DECIMAL(5,2), -- Threat intelligence contribution
    vulnerability_age_component DECIMAL(5,2), -- Age-based decay/modifier
    business_impact_component DECIMAL(5,2),   -- Financial impact contribution
    -- ML model output
    ml_risk_score DECIMAL(5,2),          -- Raw output from XGBoost/LightGBM model (0-100)
    -- Final score and tier
    dynamic_risk_score DECIMAL(5,2) NOT NULL, -- Final combined score (0-100)
    priority_tier VARCHAR(2) NOT NULL,   -- 'P0', 'P1', 'P2', 'P3'
    -- Score rationale and explainability
    top_contributing_factors JSONB,      -- Top 3 factors with percentages (for UI)
    shap_values JSONB,                   -- SHAP values for explainability (optional)
    natural_language_explanation TEXT,   -- LLM-generated human-readable rationale
    -- Metadata
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    model_version VARCHAR(20),           -- Version of ML model used
    calculation_duration_ms INTEGER,     -- Performance metric
    -- Feedback loop for model improvement
    actual_exploited BOOLEAN,            -- Ground truth (if known, for training)
    exploited_at TIMESTAMP WITH TIME ZONE, -- When exploitation was observed
    UNIQUE(asset_vulnerability_id)
);

-- Indexes for risk_scores
CREATE INDEX idx_risk_scores_dynamic_risk_score ON risk_scores(dynamic_risk_score);
CREATE INDEX idx_risk_scores_priority_tier ON risk_scores(priority_tier);
CREATE INDEX idx_risk_scores_calculated_at ON risk_scores(calculated_at);
CREATE INDEX idx_risk_scores_model_version ON risk_scores(model_version);

-- 6. Additional Tables for Innovations (Summary)

-- 6.1 Attack Path Simulation Results
CREATE TABLE attack_path_simulations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    simulation_name VARCHAR(100),
    algorithm VARCHAR(20),               -- 'monte-carlo', 'graph-based'
    parameters JSONB,                    -- Simulation parameters (num_iterations, etc.)
    results JSONB,                       -- Path probabilities, critical nodes
    crown_jewel_asset_id UUID REFERENCES assets(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6.2 Business Impact Quantification (FAIR-inspired)
CREATE TABLE business_impact (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id),
    asset_value DECIMAL(15,2),           -- Asset value in USD
    annual_rate_of_occurrence DECIMAL(5,4), -- ARO
    exposure_factor DECIMAL(3,2),        -- EF (0.0-1.0)
    single_loss_expectancy DECIMAL(15,2), -- SLE = AV * EF
    annual_loss_expectancy DECIMAL(15,2), -- ALE = SLE * ARO
    -- Incident response costs
    incident_response_cost DECIMAL(15,2),
    regulatory_fine_potential DECIMAL(15,2),
    reputational_damage_multiplier DECIMAL(3,2),
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6.3 Federated Learning Updates (for community-driven intelligence)
CREATE TABLE federated_learning_updates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    contributing_organization_id VARCHAR(100), -- Hashed/org ID for privacy
    update_type VARCHAR(20),             -- 'model-weights', 'feature-importance', 'threat-signals'
    update_data JSONB,                   -- Encrypted/update payload
    differential_privacy_epsilon DECIMAL(3,2), -- Privacy budget used
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6.4 Honeypot Interactions (Adversary Emulation)
CREATE TABLE honeypot_interactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    honeypot_id VARCHAR(100),            -- Identifier for the honeypot/decoy
    vulnerability_id UUID REFERENCES vulnerabilities(id),
    source_ip INET,
    attack_timestamp TIMESTAMP WITH TIME ZONE,
    attack_vector VARCHAR(100),          -- e.g., 'http-get', 'ssh-brute', 'smb-exploit'
    payload TEXT,
    success BOOLEAN,                     -- Did exploitation succeed?
    data_exfiltrated BOOLEAN,            -- Indicates if data was accessed
    -- Threat intelligence derived
    threat_actor_attribution VARCHAR(100),
    campaign VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6.5 Patch Testing Results (Chaos Engineering/Canary)
CREATE TABLE patch_testing_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_vulnerability_id UUID NOT NULL REFERENCES asset_vulnerabilities(id),
    patch_id VARCHAR(100),               -- Identifier for patch being tested
    test_environment VARCHAR(50),        -- 'staging', 'canary', 'chaos-mesh'
    test_type VARCHAR(30),               -- 'functional', 'performance', 'security', 'chaos'
    passed BOOLEAN,
    failure_reason TEXT,
    performance_impact DECIMAL(5,2),     -- % change in key metrics
    security_regression BOOLEAN,         -- Did patch introduce new vuln?
    tested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6.6 Blockchain Audit Logs (Simplified - in reality would be on actual blockchain)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_vulnerability_id UUID NOT NULL REFERENCES asset_vulnerabilities(id),
    action VARCHAR(50),                  -- 'score-calculated', 'tier-changed', 'patched', 'false-positive-closed'
    old_value JSONB,                     -- Previous state
    new_value JSONB,                     -- New state
    triggered_by VARCHAR(100),           -- 'system', 'user:username', 'model-retrain'
    transaction_hash VARCHAR(66),        -- Simulated blockchain tx hash (0x...)
    block_number BIGINT,                 -- Simulated block number
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for audit_logs
CREATE INDEX idx_audit_logs_asset_vulnerability_id ON audit_logs(asset_vulnerability_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- 7. Triggers for automatic updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to tables that need it
DO $$
DECLARE
    tables TEXT[] := ARRAY['vulnerabilities', 'assets', 'asset_vulnerabilities', 'threat_intelligence', 'risk_scores', 'business_impact', 'federated_learning_updates', 'honeypot_interactions', 'patch_testing_results', 'audit_logs'];
    t TEXT;
BEGIN
    FOREACH t IN ARRAY tables LOOP
        EXECUTE format('
            DROP TRIGGER IF EXISTS update_%s_updated_at ON %s;
            CREATE TRIGGER update_%s_updated_at
            BEFORE UPDATE ON %s
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        ', t, t, t, t);
    END LOOP;
END $$;

-- 8. Views for Common Queries

-- View: High-risk vulnerabilities requiring immediate attention (P0/P1)
CREATE VIEW high_priority_vulnerabilities AS
SELECT
    v.cve_id,
    v.description,
    av.asset_id,
    a.hostname,
    a.asset_type,
    rs.dynamic_risk_score,
    rs.priority_tier,
    rs.top_contributing_factors,
    rs.natural_language_explanation,
    av.status,
    av.detected_at
FROM risk_scores rs
JOIN asset_vulnerabilities av ON rs.asset_vulnerability_id = av.id
JOIN vulnerabilities v ON av.vulnerability_id = v.id
JOIN assets a ON av.asset_id = a.id
WHERE rs.priority_tier IN ('P0', 'P1')
ORDER BY rs.dynamic_risk_score DESC;

-- View: Asset risk summary
CREATE VIEW asset_risk_summary AS
SELECT
    a.id AS asset_id,
    a.hostname,
    a.asset_type,
    a.business_importance,
    a.internet_exposure,
    COUNT(av.id) AS total_vulnerabilities,
    COUNT(CASE WHEN rs.priority_tier = 'P0' THEN 1 END) AS p0_count,
    COUNT(CASE WHEN rs.priority_tier = 'P1' THEN 1 END) AS p1_count,
    COUNT(CASE WHEN rs.priority_tier = 'P2' THEN 1 END) AS p2_count,
    COUNT(CASE WHEN rs.priority_tier = 'P3' THEN 1 END) AS p3_count,
    AVG(rs.dynamic_risk_score) AS average_risk_score,
    MAX(rs.dynamic_risk_score) AS max_risk_score
FROM assets a
LEFT JOIN asset_vulnerabilities av ON a.id = av.asset_id
LEFT JOIN risk_scores rs ON av.id = rs.asset_vulnerability_id
GROUP BY a.id, a.hostname, a.asset_type, a.business_importance, a.internet_exposure;

-- View: Exploit prediction accuracy (for model evaluation)
CREATE VIEW exploit_prediction_accuracy AS
SELECT
    v.cve_id,
    rs.ml_risk_score,
    rs.dynamic_risk_score,
    rs.actual_exploited,
    rs.exploited_at,
    CASE
        WHEN rs.ml_risk_score >= 70 AND rs.actual_exploited THEN TRUE
        WHEN rs.ml_risk_score < 70 AND NOT rs.actual_exploited THEN TRUE
        ELSE FALSE
    END AS ml_prediction_correct,
    CASE
        WHEN rs.dynamic_risk_score >= 70 AND rs.actual_exploited THEN TRUE
        WHEN rs.dynamic_risk_score < 70 AND NOT rs.actual_exploited THEN TRUE
        ELSE FALSE
    END AS dynamic_prediction_correct
FROM risk_scores rs
JOIN asset_vulnerabilities av ON rs.asset_vulnerability_id = av.id
JOIN vulnerabilities v ON av.vulnerability_id = v.id
WHERE rs.actual_exploited IS NOT NULL;