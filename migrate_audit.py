
import sqlite3
import os

# Locate the existing database
database_path = os.path.join(
    'instance',
    'trustvault.db'
)

connection = sqlite3.connect(database_path)
cursor = connection.cursor()

# Get existing columns
cursor.execute("PRAGMA table_info(audit_log)")
columns = [column[1] for column in cursor.fetchall()]

# Add previous_hash if it does not exist
if 'previous_hash' not in columns:
    cursor.execute(
        "ALTER TABLE audit_log ADD COLUMN previous_hash VARCHAR(64)"
    )
    print("previous_hash column added.")

# Add entry_hash if it does not exist
if 'entry_hash' not in columns:
    cursor.execute(
        "ALTER TABLE audit_log ADD COLUMN entry_hash VARCHAR(64)"
    )
    print("entry_hash column added.")

connection.commit()
connection.close()

print("Database migration completed successfully!")
