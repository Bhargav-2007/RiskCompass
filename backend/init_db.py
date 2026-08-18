import os
import sqlalchemy
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite:///./riskcompass.dev.db"
)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = sqlalchemy.create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

# Import our metadata from db.py
from app.db import metadata

# Drop all tables and recreate
metadata.drop_all(engine)
metadata.create_all(engine)

# Check the tables
inspector = sqlalchemy.inspect(engine)
print("Tables created:", inspector.get_table_names())
for table_name in inspector.get_table_names():
    print(f"\nTable: {table_name}")
    for column in inspector.get_columns(table_name):
        print(f"  {column['name']}: {column['type']}")