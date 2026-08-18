import sqlalchemy
from app.db import engine, metadata

# Reflect existing tables
metadata.reflect(bind=engine)
print("Tables in database:")
for table in metadata.tables.values():
    print(f"  {table.name}:")
    for col in table.columns:
        print(f"    {col.name}: {col.type} nullable={col.nullable} default={col.default}")