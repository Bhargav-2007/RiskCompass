import os
import databases
import sqlalchemy
from dotenv import load_dotenv
import uuid

load_dotenv()

# Database URL from environment variable, default to SQLite for development
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite:///./riskcompass.dev.db"
)

# For PostgreSQL, we need to adjust the URL if using asyncpg
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# SQLAlchemy engine for migrations and table creation
engine = sqlalchemy.create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

# Databases instance for async queries
# For SQLite, we don't need min_size and max_size (they are for PostgreSQL)
if DATABASE_URL.startswith("sqlite"):
    database = databases.Database(DATABASE_URL)
else:
    database = databases.Database(
        DATABASE_URL,
        min_size=1,
        max_size=10,
    )

# Metadata for SQLAlchemy tables (we'll reflect from schema or define)
metadata = sqlalchemy.MetaData()

# We'll define tables here or import from schema. For now, we'll rely on the schema.sql
# and use raw SQL in the repository. Alternatively, we can use SQLAlchemy Table definitions.
# Let's define the core tables we need for Phase 1.

# Vulnerabilities table
vulnerabilities = sqlalchemy.Table(
    "vulnerabilities",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String(36), primary_key=True, default=lambda: str(uuid.uuid4())),
    sqlalchemy.Column("cve_id", sqlalchemy.String(20), unique=True, nullable=False),
    sqlalchemy.Column("cvss_v3_score", sqlalchemy.Numeric(3, 1)),
    sqlalchemy.Column("cvss_v3_vector", sqlalchemy.String(50)),
    sqlalchemy.Column("cvss_v4_score", sqlalchemy.Numeric(3, 1)),
    sqlalchemy.Column("cvss_v4_vector", sqlalchemy.String(50)),
    sqlalchemy.Column("epss_score", sqlalchemy.Numeric(5, 4)),
    sqlalchemy.Column("epss_percentile", sqlalchemy.Numeric(5, 4)),
    sqlalchemy.Column("kev", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("kev_date", sqlalchemy.Date),
    sqlalchemy.Column("cwe_id", sqlalchemy.String(10)),
    sqlalchemy.Column("description", sqlalchemy.Text),
    sqlalchemy.Column("references", sqlalchemy.Text),  # Changed from JSONB to Text
    sqlalchemy.Column("exploit_available", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("exploit_maturity", sqlalchemy.String(20)),
    sqlalchemy.Column("published_date", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("modified_date", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("threat_velocity_score", sqlalchemy.Numeric(3, 2)),
    sqlalchemy.Column("exploit_prediction_30d", sqlalchemy.Numeric(5, 4)),
    sqlalchemy.Column("exploit_prediction_60d", sqlalchemy.Numeric(5, 4)),
    sqlalchemy.Column("exploit_prediction_90d", sqlalchemy.Numeric(5, 4)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
    sqlalchemy.Column("updated_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
)

# Assets table
assets = sqlalchemy.Table(
    "assets",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String(36), primary_key=True, default=lambda: str(uuid.uuid4())),
    sqlalchemy.Column("asset_tag", sqlalchemy.String(100), unique=True),
    sqlalchemy.Column("hostname", sqlalchemy.String(255)),
    sqlalchemy.Column("ip_address", sqlalchemy.String(255)),  # Changed from INET to String
    sqlalchemy.Column("mac_address", sqlalchemy.String(17)),  # Changed from MACADDR to String
    sqlalchemy.Column("asset_type", sqlalchemy.String(50)),
    sqlalchemy.Column("os", sqlalchemy.String(100)),
    sqlalchemy.Column("os_version", sqlalchemy.String(50)),
    sqlalchemy.Column("internet_exposure", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("data_sensitivity", sqlalchemy.String(20)),
    sqlalchemy.Column("business_importance", sqlalchemy.Integer),
    sqlalchemy.Column("asset_criticality_score", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("owner_team", sqlalchemy.String(100)),
    sqlalchemy.Column("owner_email", sqlalchemy.String(255)),
    sqlalchemy.Column("cloud_provider", sqlalchemy.String(20)),
    sqlalchemy.Column("cloud_region", sqlalchemy.String(50)),
    sqlalchemy.Column("cloud_instance_type", sqlalchemy.String(50)),
    sqlalchemy.Column("tags", sqlalchemy.Text, server_default=sqlalchemy.text("'{}'")),  # Changed from JSONB to Text
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
    sqlalchemy.Column("updated_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
    sqlalchemy.Column("last_scanned", sqlalchemy.DateTime(timezone=True)),
)

# Asset-Vulnerability mapping
asset_vulnerabilities = sqlalchemy.Table(
    "asset_vulnerabilities",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String(36), primary_key=True, default=lambda: str(uuid.uuid4())),
    sqlalchemy.Column("asset_id", sqlalchemy.String(36), sqlalchemy.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
    sqlalchemy.Column("vulnerability_id", sqlalchemy.String(36), sqlalchemy.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
    sqlalchemy.Column("status", sqlalchemy.String(20), default="open"),
    sqlalchemy.Column("detected_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
    sqlalchemy.Column("patched_at", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("asset_specific_cvss", sqlalchemy.Numeric(3, 1)),
    sqlalchemy.Column("exploitability_adjustment", sqlalchemy.Numeric(3, 2)),
    sqlalchemy.Column("on_attack_path_to_crown_jewel", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("attack_path_probability", sqlalchemy.Numeric(5, 4)),
    sqlalchemy.Column("asset_specific_business_impact", sqlalchemy.Numeric(10, 2)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
    sqlalchemy.Column("updated_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
    sqlalchemy.UniqueConstraint("asset_id", "vulnerability_id", name="_asset_vulnerability_uc"),
)

# Risk scores table
risk_scores = sqlalchemy.Table(
    "risk_scores",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String(36), primary_key=True, default=lambda: str(uuid.uuid4())),
    sqlalchemy.Column("asset_vulnerability_id", sqlalchemy.String(36), sqlalchemy.ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"), nullable=False),
    sqlalchemy.Column("cvss_base_score", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("epss_component", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("kev_component", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("asset_criticality_component", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("exposure_component", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("exploit_availability_component", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("threat_activity_component", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("vulnerability_age_component", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("business_impact_component", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("ml_risk_score", sqlalchemy.Numeric(5, 2)),
    sqlalchemy.Column("dynamic_risk_score", sqlalchemy.Numeric(5, 2), nullable=False),
    sqlalchemy.Column("priority_tier", sqlalchemy.String(2), nullable=False),
    sqlalchemy.Column("top_contributing_factors", sqlalchemy.Text),  # Changed from JSONB to Text
    sqlalchemy.Column("shap_values", sqlalchemy.Text),  # Changed from JSONB to Text
    sqlalchemy.Column("natural_language_explanation", sqlalchemy.Text),
    sqlalchemy.Column("calculated_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
    sqlalchemy.Column("model_version", sqlalchemy.String(20)),
    sqlalchemy.Column("calculation_duration_ms", sqlalchemy.Integer),
    sqlalchemy.Column("actual_exploited", sqlalchemy.Boolean),
    sqlalchemy.Column("exploited_at", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.UniqueConstraint("asset_vulnerability_id", name="_risk_score_uc"),
)

# We'll also define the threat_intelligence table for completeness
threat_intelligence = sqlalchemy.Table(
    "threat_intelligence",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String(36), primary_key=True, default=lambda: str(uuid.uuid4())),
    sqlalchemy.Column("vulnerability_id", sqlalchemy.String(36), sqlalchemy.ForeignKey("vulnerabilities.id", ondelete="SET NULL")),
    sqlalchemy.Column("source", sqlalchemy.String(100)),
    sqlalchemy.Column("threat_type", sqlalchemy.String(50)),
    sqlalchemy.Column("threat_actor", sqlalchemy.String(100)),
    sqlalchemy.Column("campaign", sqlalchemy.String(100)),
    sqlalchemy.Column("dark_web_mentions", sqlalchemy.Integer, default=0),
    sqlalchemy.Column("dark_web_sentiment", sqlalchemy.Numeric(3, 2)),
    sqlalchemy.Column("exploit_code_available", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("exploit_code_url", sqlalchemy.Text),
    sqlalchemy.Column("first_seen", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("last_seen", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("activity_score", sqlalchemy.Numeric(3, 2)),
    sqlalchemy.Column("references", sqlalchemy.Text),  # Changed from JSONB to Text
    sqlalchemy.Column("confidence", sqlalchemy.Numeric(3, 2)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
    sqlalchemy.Column("updated_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("CURRENT_TIMESTAMP")),
)

async def connect_to_database():
    """Connect to the database."""
    if not database.is_connected:
        await database.connect()

async def disconnect_from_database():
    """Disconnect from the database."""
    if database.is_connected:
        await database.disconnect()

def create_tables():
    """Create tables in the database. This is for development; use migrations in production."""
    metadata.drop_all(engine)
    metadata.create_all(engine)