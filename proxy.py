"""
SOCKS5 and HTTP proxy with web UI using mitmproxy + aiohttp.
"""
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from aiohttp import web

import asyncio
import sys

from addon import ProxyAddon
from web import create_app


async def start_proxy(
    listen_host: str = "0.0.0.0",
    webui_host: str = "127.0.0.1",
    http_port: int = 8080,
    socks_port: int = 8081,
    web_port: int = 8082,
):
    addon = ProxyAddon()

    opts = options.Options(
        listen_host=listen_host,
        listen_port=http_port,
        mode=[
            f"regular@{http_port}",
            f"socks5@{socks_port}",
        ],
    )

    master = DumpMaster(opts)
    master.addons.add(addon)
    addon.master = master

    # Start web UI
    app = create_app(addon)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, listen_host, web_port)
    await site.start()

    print(f"HTTP   proxy:  http://{listen_host}:{http_port}")
    print(f"SOCKS5 proxy:  socks5://{listen_host}:{socks_port}")
    print(f"Web UI:        http://{webui_host}:{web_port}")

    await master.run()


def main():
    host = "0.0.0.0"
    web_host = "127.0.0.1"
    http_port = 8080
    socks_port = 8081
    web_port = 8082

    if len(sys.argv) > 1:
        http_port = int(sys.argv[1])
    if len(sys.argv) > 2:
        socks_port = int(sys.argv[2])
    if len(sys.argv) > 3:
        web_port = int(sys.argv[3])
    if len(sys.argv) > 4:
        host = sys.argv[4]

    asyncio.run(start_proxy(host, web_host, http_port, socks_port, web_port))


if __name__ == "__main__":
    main()
