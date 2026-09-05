## 2024-03-24 - SQLAlchemy Index Creation on Existing Tables
**Learning:** `Base.metadata.create_all()` in SQLAlchemy does not add missing indices to tables that already exist. If Alembic (or another migration tool) is not in use, you must use raw SQL (like `CREATE INDEX IF NOT EXISTS`) in the app lifecycle/startup to ensure the index is deployed to existing databases.
**Action:** Next time adding an index to an ORM model without a migration system, ensure there is a mechanism to apply that index to existing tables, such as running raw SQL during the application's lifespan setup.
