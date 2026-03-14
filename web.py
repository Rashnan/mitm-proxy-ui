"""
Web UI server: dashboard + API for flow actions, allowlist/blocklist management.
"""
import json
import os
from aiohttp import web
import db as database

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def create_app(addon) -> web.Application:
    app = web.Application()
    app["addon"] = addon

    app.router.add_get("/", handle_index)
    app.router.add_get("/ws", handle_ws)

    # Requests/flows
    app.router.add_get("/api/requests", handle_get_requests)
    app.router.add_delete("/api/requests", handle_clear_requests)
    app.router.add_delete("/api/logs", handle_delete_all_logs)

    # Flow actions
    app.router.add_get("/api/flow/{id}", handle_get_flow)
    app.router.add_delete("/api/flow/{id}", handle_delete_flow)
    app.router.add_post("/api/flow/{id}/replay", handle_replay_flow)
    app.router.add_post("/api/flow/{id}/duplicate", handle_duplicate_flow)
    app.router.add_post("/api/flow/{id}/revert", handle_revert_flow)
    app.router.add_post("/api/flow/{id}/resume", handle_resume_flow)
    app.router.add_post("/api/flow/{id}/kill", handle_kill_flow)
    app.router.add_put("/api/flow/{id}", handle_edit_flow)
    app.router.add_get("/api/flow/{id}/request/content", handle_download_request)
    app.router.add_get("/api/flow/{id}/response/content", handle_download_response)

    # Bulk actions
    app.router.add_post("/api/flows/resume", handle_resume_all)
    app.router.add_post("/api/flows/kill", handle_kill_all)

    # Rules & settings
    app.router.add_get("/api/rules", handle_get_rules)
    app.router.add_post("/api/rules", handle_set_rules)
    app.router.add_get("/api/settings", handle_get_settings)
    app.router.add_post("/api/settings", handle_set_settings)

    return app


async def handle_index(request: web.Request):
    return web.FileResponse(os.path.join(STATIC_DIR, "index.html"))


async def handle_ws(request: web.Request):
    addon = request.app["addon"]
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    addon.register_ws(ws)
    try:
        async for msg in ws:
            pass
    finally:
        addon.unregister_ws(ws)
    return ws


async def handle_get_requests(request: web.Request):
    addon = request.app["addon"]
    entries = list(addon.entries.values())[-500:]
    return web.json_response([r.to_dict() for r in entries])


async def handle_clear_requests(request: web.Request):
    """Clear in-memory view only, DB untouched."""
    addon = request.app["addon"]
    addon.entries.clear()
    addon.flows.clear()
    addon._pending.clear()
    return web.json_response({"status": "ok"})


async def handle_delete_all_logs(request: web.Request):
    """Destructively delete all logs from memory and DB."""
    addon = request.app["addon"]
    addon.entries.clear()
    addon.flows.clear()
    addon._pending.clear()
    database.clear_entries()
    return web.json_response({"status": "ok"})


# --- Flow detail & actions ---

async def handle_get_flow(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    entry = addon.get_entry(fid)
    if not entry:
        return web.json_response({"error": "not found"}, status=404)
    flow = addon.get_flow(fid)
    detail = entry.to_dict()
    if flow:
        # Add full request/response body preview (text, truncated)
        if flow.request.raw_content:
            try:
                detail["request_body"] = flow.request.get_text(strict=False)[:10000]
            except Exception:
                detail["request_body"] = f"<binary {len(flow.request.raw_content)} bytes>"
        if flow.response and flow.response.raw_content:
            try:
                detail["response_body"] = flow.response.get_text(strict=False)[:10000]
            except Exception:
                detail["response_body"] = f"<binary {len(flow.response.raw_content)} bytes>"
        detail["killable"] = flow.killable
        detail["modified"] = flow.modified()
        # Include original data if modified
        if flow.modified() and hasattr(flow, '_backup'):
            backup = flow._backup
            if backup:
                orig = {}
                if "request" in backup:
                    orig_req = backup["request"]
                    # backup is state dict, reconstruct readable form
                    from mitmproxy.http import Request
                    try:
                        r = Request.from_state(orig_req)
                        orig["request_method"] = r.method
                        orig["request_url"] = r.pretty_url
                        orig["request_headers"] = [[k, v] for k, v in r.headers.items(True)]
                        if r.raw_content:
                            try:
                                orig["request_body"] = r.get_text(strict=False)[:10000]
                            except Exception:
                                orig["request_body"] = f"<binary {len(r.raw_content)} bytes>"
                    except Exception:
                        pass
                if "response" in backup and backup["response"]:
                    from mitmproxy.http import Response
                    try:
                        r = Response.from_state(backup["response"])
                        orig["response_status_code"] = r.status_code
                        orig["response_reason"] = r.reason
                        orig["response_headers"] = [[k, v] for k, v in r.headers.items(True)]
                        if r.raw_content:
                            try:
                                orig["response_body"] = r.get_text(strict=False)[:10000]
                            except Exception:
                                orig["response_body"] = f"<binary {len(r.raw_content)} bytes>"
                    except Exception:
                        pass
                if orig:
                    detail["original"] = orig
    return web.json_response(detail)


async def handle_edit_flow(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    data = await request.json()
    if addon.edit_flow(fid, data):
        return web.json_response({"status": "ok"})
    return web.json_response({"error": "edit failed or not found"}, status=400)


async def handle_delete_flow(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    if addon.delete_flow(fid):
        return web.json_response({"status": "ok"})
    return web.json_response({"error": "not found"}, status=404)


async def handle_replay_flow(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    result = addon.replay_flow(fid)
    if result:
        return web.json_response({"status": "ok", "id": result})
    return web.json_response({"error": "flow not found"}, status=404)


async def handle_duplicate_flow(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    new_id = addon.duplicate_flow(fid)
    if new_id:
        return web.json_response({"status": "ok", "id": new_id})
    return web.json_response({"error": "flow not found"}, status=404)


async def handle_revert_flow(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    if addon.revert_flow(fid):
        return web.json_response({"status": "ok"})
    return web.json_response({"error": "not modified or not found"}, status=400)


async def handle_resume_flow(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    if addon.resume_flow(fid):
        return web.json_response({"status": "ok"})
    return web.json_response({"error": "not intercepted or not found"}, status=400)


async def handle_kill_flow(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    if addon.kill_flow(fid):
        return web.json_response({"status": "ok"})
    return web.json_response({"error": "not killable or not found"}, status=400)


async def handle_download_request(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    flow = addon.get_flow(fid)
    if not flow or not flow.request.raw_content:
        return web.json_response({"error": "no content"}, status=404)
    return web.Response(
        body=flow.request.raw_content,
        content_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="request_{fid}"'},
    )


async def handle_download_response(request: web.Request):
    addon = request.app["addon"]
    fid = request.match_info["id"]
    flow = addon.get_flow(fid)
    if not flow or not flow.response or not flow.response.raw_content:
        return web.json_response({"error": "no content"}, status=404)
    ct = flow.response.headers.get("content-type", "application/octet-stream")
    return web.Response(
        body=flow.response.raw_content,
        content_type=ct,
        headers={"Content-Disposition": f'attachment; filename="response_{fid}"'},
    )


async def handle_resume_all(request: web.Request):
    addon = request.app["addon"]
    addon.resume_all()
    return web.json_response({"status": "ok"})


async def handle_kill_all(request: web.Request):
    addon = request.app["addon"]
    addon.kill_all()
    return web.json_response({"status": "ok"})


# --- Rules & Settings ---

async def handle_get_rules(request: web.Request):
    addon = request.app["addon"]
    return web.json_response({
        "allowlist": addon.allowlist,
        "blocklist": addon.blocklist,
    })


async def handle_set_rules(request: web.Request):
    addon = request.app["addon"]
    data = await request.json()
    if "allowlist" in data:
        addon.allowlist = [s.strip() for s in data["allowlist"] if s.strip()]
    if "blocklist" in data:
        addon.blocklist = [s.strip() for s in data["blocklist"] if s.strip()]
    addon.save_settings()
    return web.json_response({
        "allowlist": addon.allowlist,
        "blocklist": addon.blocklist,
    })


async def handle_get_settings(request: web.Request):
    addon = request.app["addon"]
    return web.json_response({
        "ssl_passthrough": addon.ssl_passthrough,
        "intercept_requests": addon.intercept_requests,
        "intercept_responses": addon.intercept_responses,
        "intercept_filter": addon.intercept_filter,
    })


async def handle_set_settings(request: web.Request):
    addon = request.app["addon"]
    data = await request.json()
    if "ssl_passthrough" in data:
        addon.ssl_passthrough = bool(data["ssl_passthrough"])
    if "intercept_requests" in data:
        addon.intercept_requests = bool(data["intercept_requests"])
    if "intercept_responses" in data:
        addon.intercept_responses = bool(data["intercept_responses"])
    if "intercept_filter" in data:
        addon.intercept_filter = str(data["intercept_filter"])
    addon.save_settings()
    return web.json_response({
        "ssl_passthrough": addon.ssl_passthrough,
        "intercept_requests": addon.intercept_requests,
        "intercept_responses": addon.intercept_responses,
        "intercept_filter": addon.intercept_filter,
    })
