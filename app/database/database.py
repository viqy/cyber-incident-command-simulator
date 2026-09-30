from pathlib import Path
import sqlite3


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "simulator.db"


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        check_same_thread=False,
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database() -> None:
    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                incident_id TEXT PRIMARY KEY,
                analyst TEXT,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                finding TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id)
                    REFERENCES investigations(incident_id)
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                performed_by TEXT NOT NULL,
                performed_at TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY (incident_id)
                    REFERENCES investigations(incident_id)
            )
            """
        )

        connection.commit()

    finally:
        connection.close()