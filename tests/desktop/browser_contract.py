"""Runs only inside the task sandbox; no provider key or external page is used."""

import asyncio
import json
import time
from importlib.metadata import version
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path("/workspace")


def listeners():
    values = []
    for name in ("tcp", "tcp6"):
        for row in Path("/proc/net", name).read_text().splitlines()[1:]:
            fields = row.split()
            if fields[3] == "0A":
                values.append({"table": name, "address": fields[1]})
    return values


def browser_processes():
    result = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / "cmdline").read_bytes().decode(errors="replace").split("\0")
            if not args or not args[0] or "chromium" not in args[0]:
                continue
            status = (entry / "status").read_text()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        result.append(
            {
                "pid": int(entry.name),
                "args": [a for a in args if a],
                "seccomp": fields.get("Seccomp", "").strip(),
                "no_new_privs": fields.get("NoNewPrivs", "").strip(),
            }
        )
    return result


async def main():
    assert not listeners(), "Unexpected initial TCP listener"
    (
        ROOT / "page.html"
    ).write_text("""<!doctype html><html><head><title>mano-browser-contract</title>
<style>body{font:24px sans-serif;background:#101827;color:#eaf0ff;padding:60px}
button{font:inherit;padding:12px 24px;background:#7ac8ff;border:0;border-radius:8px}</style></head>
<body><h1>mano browser contract</h1>
<button onclick="document.querySelector('#result').textContent='clicked 1'">
Verify action</button><p id="result">waiting</p></body></html>""")
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path="/usr/bin/chromium",
            headless=False,
            chromium_sandbox=True,
            args=["--ozone-platform=wayland"],
            timeout=30000,
        )
        try:
            context = await browser.new_context(viewport={"width": 1100, "height": 650})
            await context.tracing.start(screenshots=True, snapshots=True, sources=True)
            page = await context.new_page()
            await page.goto("file:///workspace/page.html")
            await page.get_by_role("button", name="Verify action").click()
            assert await page.locator("#result").inner_text() == "clicked 1"
            processes = browser_processes()
            assert processes, "No actual Chromium process observed"
            for proc in processes:
                assert "--no-sandbox" not in proc["args"], proc
                assert not any(a.startswith("--remote-debugging-port") for a in proc["args"]), proc
            assert any("--remote-debugging-pipe" in proc["args"] for proc in processes), processes
            session = await browser.new_browser_cdp_session()
            reported = (await session.send("SystemInfo.getProcessInfo"))["processInfo"]
            renderers = []
            for proc in reported:
                if proc["type"] != "renderer":
                    continue
                pid = int(proc["id"])
                status = Path(f"/proc/{pid}/status").read_text()
                fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
                renderers.append(
                    {
                        "pid": pid,
                        "name": fields.get("Name", "").strip(),
                        "seccomp": fields.get("Seccomp", "").strip(),
                        "no_new_privs": fields.get("NoNewPrivs", "").strip(),
                    }
                )
            (ROOT / "renderer-observations.json").write_text(
                json.dumps(
                    {
                        "reported": reported,
                        "kernel_status": renderers,
                    },
                    indent=2,
                )
                + "\n"
            )
            assert renderers and all(proc["seccomp"] == "2" for proc in renderers), renderers
            assert not listeners(), "Unexpected TCP listener, including exposed CDP"
            await page.screenshot(path=str(ROOT / "browser-page.png"))
            report = {
                "playwright_version": version("playwright"),
                "chromium_version": browser.version,
                "executable_path": "/usr/bin/chromium",
                "headless": False,
                "sandbox_requested": True,
                "locator_result": await page.locator("#result").inner_text(),
                "title": await page.title(),
                "processes": processes,
                "tcp_listeners": listeners(),
                "renderer_seccomp_enforced": True,
                "renderer_kernel_status": renderers,
                "human_display_access": False,
            }
            (ROOT / "browser-ready.json").write_text(json.dumps(report, indent=2) + "\n")
            deadline = time.monotonic() + 20
            while not (ROOT / "observer-done").exists():
                if time.monotonic() > deadline:
                    raise RuntimeError("Independent window observer timed out")
                await asyncio.sleep(0.1)
            await context.tracing.stop(path=str(ROOT / "browser-trace.zip"))
            (ROOT / "browser-contract.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
