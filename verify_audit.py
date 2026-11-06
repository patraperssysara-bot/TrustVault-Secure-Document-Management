
import sqlite3
import hashlib
import json
import os
from datetime import datetime

database_path = os.path.join("instance", "trustvault.db")

connection = sqlite3.connect(database_path)
cursor = connection.cursor()

cursor.execute("""
    SELECT id, user_id, action, document_id,
           timestamp, previous_hash, entry_hash
    FROM audit_log
    WHERE entry_hash IS NOT NULL
    ORDER BY id ASC
""")

records = cursor.fetchall()

previous_hash = "GENESIS"
all_valid = True

for record in records:
    log_id, user_id, action, document_id, timestamp, stored_previous, stored_hash = record

    if stored_previous != previous_hash:
        print(f"FAILED: Previous hash mismatch at Log ID {log_id}")
        all_valid = False
        break

    # Convert SQLite timestamp to Python ISO format
    formatted_timestamp = datetime.fromisoformat(
        timestamp
    ).isoformat()

    audit_data = {
        "id": log_id,
        "user_id": user_id,
        "action": action,
        "document_id": document_id,
        "timestamp": formatted_timestamp
    }

    serialized_data = json.dumps(
        audit_data,
        sort_keys=True,
        separators=(",", ":")
    )

    hash_input = previous_hash + serialized_data

    calculated_hash = hashlib.sha256(
        hash_input.encode("utf-8")
    ).hexdigest()

    if calculated_hash != stored_hash:
        print(f"FAILED: Hash mismatch at Log ID {log_id}")
        all_valid = False
        break

    previous_hash = stored_hash

connection.close()

if all_valid:
    print("SUCCESS: Audit hash chain is valid!")
    print(f"Verified records: {len(records)}")
else:
    print("WARNING: Audit chain integrity check failed!")
