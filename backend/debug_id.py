import sqlalchemy
from app.db import engine, vulnerabilities

# Let's check the table definition in the metadata
print("Vulnerabilities table from metadata:")
print(vulnerabilities)
print("\nColumns:")
for col in vulnerabilities.columns:
    print(f"  {col.name}: {col.type} (primary_key={col.primary_key})")

# Now, let's insert a row and see what happens
with engine.connect() as conn:
    # Start a transaction
    trans = conn.begin()
    try:
        # Insert a test row
        insert_stmt = vulnerabilities.insert().values(
            id="test-id-string",
            cve_id="CVE-2023-TEST",
            description="Test"
        )
        result = conn.execute(insert_stmt)
        print(f"Inserted row with id: {insert_stmt.compiled.params['id']}")
        
        # Now, select it back
        select_stmt = vulnerabilities.select().where(vulnerabilities.c.cve_id == "CVE-2023-TEST")
        result = conn.execute(select_stmt)
        row = result.fetchone()
        if row:
            print(f"Retrieved row: {row}")
            print(f"Types: {[type(x) for x in row]}")
            columns = result.keys()
            for col, val in zip(columns, row):
                print(f"  {col}: {val} (type: {type(val)})")
        else:
            print("No row found")
        
        # Rollback so we don't leave test data
        trans.rollback()
    except Exception as e:
        print(f"Error: {e}")
        trans.rollback()