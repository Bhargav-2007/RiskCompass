import sqlalchemy
from app.db import engine, vulnerabilities

with engine.connect() as conn:
    # Get the last inserted row
    result = conn.execute(sqlalchemy.text("SELECT * FROM vulnerabilities ORDER BY rowid DESC LIMIT 1"))
    row = result.fetchone()
    if row:
        print("Row:", row)
        print("Types:", [type(x) for x in row])
        # Get column names
        columns = result.keys()
        print("Columns:", columns)
        for col, val in zip(columns, row):
            print(f"{col}: {val} (type: {type(val)})")
    else:
        print("No rows found")