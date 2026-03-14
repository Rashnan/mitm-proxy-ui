"""
Mitmproxy addon: logs requests, enforces allow/blocklist, stores flows for actions.
"""
import asyncio
import copy
import fnmatch
import hashlib
import json
import os
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, asdict
from mitmproxy import http, tls, ctx
import db as database

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")


@dataclass
class RequestEntry:
    id: str = ""
    timestamp: float = 0.0
    method: str = ""
    url: str = ""
    host: str = ""
    port: int = 0
    scheme: str = ""
    path: str = ""
    server_ip: str = ""
    server_port: int = 0
    client_ip: str = ""
    client_port: int = 0
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    duration_ms: float = 0.0
    blocked: bool = False
    passthrough: bool = False
    intercepted: bool = False
    intercept_phase: str = ""  # "request" or "response"
    is_replay: bool = False
    modified: bool = False
    request_content_length: int = 0
    response_reason: str = ""
    request_http_version: str = ""
    response_http_version: str = ""
    request_headers: list = None
    response_headers: list = None

    def __post_init__(self):
        if self.request_headers is None:
            self.request_headers = []
        if self.response_headers is None:
            self.response_headers = []

    def to_dict(self):
        return asdict(self)


class ProxyAddon:
    def __init__(self):
        self.entries: OrderedDict[str, RequestEntry] = OrderedDict()
        self.flows: dict[str, http.HTTPFlow] = {}
        self.max_requests = 5000
        self.allowlist: list[str] = []
        self.blocklist: list[str] = []
        self.ssl_passthrough: bool = False
        self.intercept_requests: bool = False
        self.intercept_responses: bool = False
        self.intercept_filter: str = ""  # fnmatch pattern on host, empty = all
        self._pending: dict[int, tuple[str, float]] = {}
        self._intercept_phase: dict[str, str] = {}  # entry_id -> "request"|"response"
        self._force_modified: set[str] = set()  # entry IDs we've manually modified
        self._ws_clients: set = set()
        self.master = None
        self._load_settings()
        self._init_db()

    def _load_settings(self):
        try:
            with open(SETTINGS_FILE, "r") as f:
                d = json.load(f)
            self.allowlist = d.get("allowlist", [])
            self.blocklist = d.get("blocklist", [])
            self.ssl_passthrough = d.get("ssl_passthrough", False)
            self.intercept_requests = d.get("intercept_requests", False)
            self.intercept_responses = d.get("intercept_responses", False)
            self.intercept_filter = d.get("intercept_filter", "")
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save_settings(self):
        d = {
            "allowlist": self.allowlist,
            "blocklist": self.blocklist,
            "ssl_passthrough": self.ssl_passthrough,
            "intercept_requests": self.intercept_requests,
            "intercept_responses": self.intercept_responses,
            "intercept_filter": self.intercept_filter,
        }
        with open(SETTINGS_FILE, "w") as f:
            json.dump(d, f, indent=2)

    def _init_db(self):
        database.init_db()
        for d in database.load_entries(self.max_requests):
            entry = RequestEntry(**d)
            self.entries[entry.id] = entry

    def _new_id(self) -> str:
        return uuid.uuid4().hex[:12]

    def _matches_any(self, host: str, patterns: list[str]) -> bool:
        for pattern in patterns:
            if fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(host, f"*.{pattern}"):
                return True
        return False

    def _should_intercept(self, host: str) -> bool:
        if not self.intercept_filter:
            return True
        return self._matches_any(host, [p.strip() for p in self.intercept_filter.split("\n") if p.strip()])

    def _is_blocked(self, host: str) -> bool:
        if self._matches_any(host, self.blocklist):
            return True
        if self.allowlist and not self._matches_any(host, self.allowlist):
            return True
        return False

    def _broadcast(self, msg: dict):
        data = json.dumps(msg)
        dead = set()
        for ws in self._ws_clients:
            try:
                asyncio.ensure_future(ws.send_str(data))
            except Exception:
                dead.add(ws)
        self._ws_clients -= dead

    def register_ws(self, ws):
        self._ws_clients.add(ws)

    def unregister_ws(self, ws):
        self._ws_clients.discard(ws)

    def _log_entry(self, entry: RequestEntry, flow: http.HTTPFlow = None):
        self.entries[entry.id] = entry
        if flow is not None:
            self.flows[entry.id] = flow
        # Trim old entries
        while len(self.entries) > self.max_requests:
            old_id, _ = self.entries.popitem(last=False)
            self.flows.pop(old_id, None)
        database.save_entry(entry)
        self._broadcast({"type": "request", "data": entry.to_dict()})

    def _update_entry(self, entry: RequestEntry):
        self.entries[entry.id] = entry
        database.save_entry(entry)
        self._broadcast({"type": "update", "data": entry.to_dict()})

    def _headers_to_list(self, headers) -> list:
        return [[k, v] for k, v in headers.items(True)]

    def _entry_from_flow(self, flow: http.HTTPFlow, entry_id: str = None) -> RequestEntry:
        eid = entry_id or self._new_id()
        entry = RequestEntry(
            id=eid,
            timestamp=flow.request.timestamp_start or time.time(),
            method=flow.request.method,
            url=flow.request.pretty_url,
            host=flow.request.pretty_host,
            port=flow.request.port,
            scheme=flow.request.scheme,
            path=flow.request.path,
            request_http_version=flow.request.http_version,
            request_content_length=len(flow.request.raw_content) if flow.request.raw_content else 0,
            request_headers=self._headers_to_list(flow.request.headers),
            intercepted=flow.intercepted,
            intercept_phase=self._intercept_phase.get(eid, "") if flow.intercepted else "",
            is_replay=bool(flow.is_replay),
            modified=flow.modified() or eid in self._force_modified,
        )
        if flow.response:
            entry.status_code = flow.response.status_code
            entry.content_length = len(flow.response.raw_content) if flow.response.raw_content else 0
            entry.content_type = flow.response.headers.get("content-type", "")
            entry.response_reason = flow.response.reason
            entry.response_http_version = flow.response.http_version
            entry.response_headers = self._headers_to_list(flow.response.headers)
            if flow.request.timestamp_start and flow.response.timestamp_end:
                entry.duration_ms = round(
                    (flow.response.timestamp_end - flow.request.timestamp_start) * 1000, 1
                )
        return entry

    def tls_clienthello(self, flow: tls.ClientHelloData):
        if not self.ssl_passthrough:
            return
        sni = flow.client_hello.sni
        host = sni or (flow.context.server.address[0] if flow.context.server.address else "unknown")

        entry = RequestEntry(
            id=self._new_id(),
            timestamp=time.time(),
            method="CONNECT",
            url=f"https://{host}:443",
            host=host,
            port=443,
            scheme="https",
            path="/",
            passthrough=True,
        )

        if self._is_blocked(host):
            entry.blocked = True
            entry.status_code = 403
            self._log_entry(entry)
            return

        entry.status_code = 200
        self._log_entry(entry)
        flow.ignore_connection = True

    def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        eid = self._new_id()

        if self._is_blocked(host):
            entry = self._entry_from_flow(flow, eid)
            entry.blocked = True
            entry.status_code = 403
            if flow.client_conn and flow.client_conn.peername:
                entry.client_ip = flow.client_conn.peername[0]
                entry.client_port = flow.client_conn.peername[1]
            self._log_entry(entry, flow)
            flow.response = http.Response.make(403, b"Blocked by proxy", {"Content-Type": "text/plain"})
            return

        # Intercept request before sending to server
        if self.intercept_requests and self._should_intercept(host):
            flow.intercept()
            self._intercept_phase[eid] = "request"

        self._pending[id(flow)] = (eid, time.time())
        # Store flow immediately so intercepted flows are accessible
        entry = self._entry_from_flow(flow, eid)
        if flow.client_conn and flow.client_conn.peername:
            entry.client_ip = flow.client_conn.peername[0]
            entry.client_port = flow.client_conn.peername[1]
        self._log_entry(entry, flow)

    def response(self, flow: http.HTTPFlow):
        key = id(flow)
        if key not in self._pending:
            return
        eid, start = self._pending.pop(key)
        if eid in self.entries:
            # Intercept response before sending to client
            if self.intercept_responses and self._should_intercept(flow.request.pretty_host):
                flow.intercept()
                self._intercept_phase[eid] = "response"
            entry = self._entry_from_flow(flow, eid)
            entry.duration_ms = round((time.time() - start) * 1000, 1)
            if flow.client_conn and flow.client_conn.peername:
                entry.client_ip = flow.client_conn.peername[0]
                entry.client_port = flow.client_conn.peername[1]
            if flow.server_conn and flow.server_conn.peername:
                entry.server_ip = flow.server_conn.peername[0]
                entry.server_port = flow.server_conn.peername[1]
            self.flows[eid] = flow
            self._update_entry(entry)

    def get_flow(self, entry_id: str) -> http.HTTPFlow | None:
        return self.flows.get(entry_id)

    def get_entry(self, entry_id: str) -> RequestEntry | None:
        return self.entries.get(entry_id)

    def replay_flow(self, entry_id: str) -> str | None:
        """Replay a flow. Returns new entry ID."""
        flow = self.flows.get(entry_id)
        if not flow:
            return None
        new_flow = flow.copy()
        new_flow.response = None
        new_flow.is_replay = "request"

        if self.master:
            self.master.commands.call("replay.client", [new_flow])
        return entry_id

    def duplicate_flow(self, entry_id: str) -> str | None:
        """Duplicate a flow. Returns new entry ID."""
        flow = self.flows.get(entry_id)
        if not flow:
            return None
        new_flow = flow.copy()
        new_id = self._new_id()
        entry = self._entry_from_flow(new_flow, new_id)
        self._log_entry(entry, new_flow)
        return new_id

    def revert_flow(self, entry_id: str) -> bool:
        """Revert a flow to its original state."""
        flow = self.flows.get(entry_id)
        if not flow or not flow.modified():
            return False
        flow.revert()
        entry = self._entry_from_flow(flow, entry_id)
        self._update_entry(entry)
        return True

    def resume_flow(self, entry_id: str) -> bool:
        """Resume an intercepted flow."""
        flow = self.flows.get(entry_id)
        if not flow or not flow.intercepted:
            return False
        flow.resume()
        self._intercept_phase.pop(entry_id, None)
        entry = self._entry_from_flow(flow, entry_id)
        self._update_entry(entry)
        return True

    def kill_flow(self, entry_id: str) -> bool:
        """Kill/abort a flow."""
        flow = self.flows.get(entry_id)
        if not flow:
            return False
        if flow.killable:
            flow.kill()
            self._force_modified.add(entry_id)
        elif flow.intercepted:
            # For intercepted responses: replace with error and resume
            flow.response = http.Response.make(502, b"Aborted", {"Content-Type": "text/plain"})
            flow.resume()
            self._intercept_phase.pop(entry_id, None)
            self._force_modified.add(entry_id)
        else:
            return False
        entry = self._entry_from_flow(flow, entry_id)
        self._update_entry(entry)
        return True

    def delete_flow(self, entry_id: str) -> bool:
        """Remove a flow from the list."""
        flow = self.flows.pop(entry_id, None)
        entry = self.entries.pop(entry_id, None)
        if flow and flow.killable:
            flow.kill()
        if entry:
            database.delete_entry(entry_id)
            self._broadcast({"type": "delete", "data": {"id": entry_id}})
            return True
        return False

    def resume_all(self):
        for eid, flow in self.flows.items():
            if flow.intercepted:
                flow.resume()
                self._intercept_phase.pop(eid, None)
                entry = self._entry_from_flow(flow, eid)
                self._update_entry(entry)

    def edit_flow(self, entry_id: str, edits: dict) -> bool:
        """Edit a flow's request/response. Works on intercepted or completed flows."""
        flow = self.flows.get(entry_id)
        if not flow:
            return False
        flow.backup()
        try:
            if "request" in edits:
                req_edits = edits["request"]
                if "method" in req_edits:
                    flow.request.method = req_edits["method"]
                if "headers" in req_edits:
                    flow.request.headers.clear()
                    for k, v in req_edits["headers"]:
                        flow.request.headers.add(k, v)
                if "url" in req_edits:
                    # Apply URL last so it updates host/port/path and Host header
                    flow.request.url = req_edits["url"]
                    flow.request.host = flow.request.pretty_host
                    flow.request.headers["Host"] = flow.request.pretty_host
                if "body" in req_edits:
                    flow.request.text = req_edits["body"]
            if "response" in edits and flow.response:
                res_edits = edits["response"]
                if "status_code" in res_edits:
                    flow.response.status_code = int(res_edits["status_code"])
                if "reason" in res_edits:
                    flow.response.reason = res_edits["reason"]
                if "headers" in res_edits:
                    flow.response.headers.clear()
                    for k, v in res_edits["headers"]:
                        flow.response.headers.add(k, v)
                if "body" in res_edits:
                    flow.response.text = res_edits["body"]
        except Exception:
            flow.revert()
            return False
        self._force_modified.add(entry_id)
        entry = self._entry_from_flow(flow, entry_id)
        self._update_entry(entry)
        return True

    def kill_all(self):
        for eid, flow in list(self.flows.items()):
            if flow.killable:
                flow.kill()
                entry = self.entries.get(eid)
                if entry:
                    entry.status_code = 0
                    self._update_entry(entry)
