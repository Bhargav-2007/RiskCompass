import sqlalchemy
from app.db import engine

# Reflect the table from the database
metadata = sqlalchemy.MetaData()
metadata.reflect(bind=engine, only=['vulnerabilities'])
table = metadata.tables['vulnerabilities']
print("Table: vulnerabilities")
for col in table.columns:
    print(f"  {col.name}: {col.type} (nullable={col.nullable}, primary_key={col.primary_key})")
    if col.default is not None:
        print(f"    default: {col.default}")