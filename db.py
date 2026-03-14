"""
SQLite persistence for request log entries.
"""
import json
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            method TEXT,
            url TEXT,
            host TEXT,
            port INTEGER,
            scheme TEXT,
            path TEXT,
            server_ip TEXT,
            server_port INTEGER,
            client_ip TEXT,
            client_port INTEGER,
            status_code INTEGER,
            content_length INTEGER,
            content_type TEXT,
            duration_ms REAL,
            blocked INTEGER,
            passthrough INTEGER,
            intercepted INTEGER,
            intercept_phase TEXT,
            is_replay INTEGER,
            modified INTEGER,
            request_content_length INTEGER,
            response_reason TEXT,
            request_http_version TEXT,
            response_http_version TEXT,
            request_headers TEXT,
            response_headers TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_entry(entry) -> None:
    d = entry.to_dict()
    d["request_headers"] = json.dumps(d["request_headers"])
    d["response_headers"] = json.dumps(d["response_headers"])
    d["blocked"] = int(d["blocked"])
    d["passthrough"] = int(d["passthrough"])
    d["intercepted"] = int(d["intercepted"])
    d["is_replay"] = int(d["is_replay"])
    d["modified"] = int(d["modified"])

    conn = get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO requests
        (id, timestamp, method, url, host, port, scheme, path,
         server_ip, server_port, client_ip, client_port,
         status_code, content_length, content_type, duration_ms,
         blocked, passthrough, intercepted, intercept_phase,
         is_replay, modified, request_content_length, response_reason,
         request_http_version, response_http_version,
         request_headers, response_headers)
        VALUES
        (:id, :timestamp, :method, :url, :host, :port, :scheme, :path,
         :server_ip, :server_port, :client_ip, :client_port,
         :status_code, :content_length, :content_type, :duration_ms,
         :blocked, :passthrough, :intercepted, :intercept_phase,
         :is_replay, :modified, :request_content_length, :response_reason,
         :request_http_version, :response_http_version,
         :request_headers, :response_headers)
    """, d)
    conn.commit()
    conn.close()


def delete_entry(entry_id: str) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM requests WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()


def clear_entries() -> None:
    conn = get_conn()
    conn.execute("DELETE FROM requests")
    conn.commit()
    conn.close()


def load_entries(limit: int = 5000) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM requests ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()

    entries = []
    for row in reversed(rows):  # oldest first
        d = dict(row)
        d["request_headers"] = json.loads(d["request_headers"]) if d["request_headers"] else []
        d["response_headers"] = json.loads(d["response_headers"]) if d["response_headers"] else []
        d["blocked"] = bool(d["blocked"])
        d["passthrough"] = bool(d["passthrough"])
        d["intercepted"] = bool(d["intercepted"])
        d["is_replay"] = bool(d["is_replay"])
        d["modified"] = bool(d["modified"])
        entries.append(d)
    return entries
