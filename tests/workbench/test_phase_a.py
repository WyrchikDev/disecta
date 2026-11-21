"""Exercise the analysis workbench with the real DISECTA server."""
import argparse
import json
from pathlib import Path
import subprocess

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]


def verify(page, url, screenshot):
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(url)
    page.wait_for_load_state("networkidle")
    page.get_by_role("button", name="Open example").click()
    expect(page.get_by_role("heading", name="branch.exe")).to_be_visible()
    page.get_by_role("button", name="Functions", exact=True).click()
    functions = page.get_by_role("table", name="Functions")
    expect(functions.get_by_role("button", name="0x140001024")).to_be_visible()
    page.get_by_label("Function confidence").select_option("confirmed")
    expect(functions.get_by_role("button", name="0x140001024")).to_have_count(0)
    page.get_by_label("Function confidence").select_option("")
    page.get_by_label("Search functions").fill("1024")
    expect(functions.get_by_role("button", name="0x140001000")).to_have_count(0)
    page.get_by_label("Search functions").clear()
    functions.get_by_role("button", name="0x140001000").click()
    graph = page.locator("#flow-canvas")
    expect(graph.locator(".flow-node")).to_have_count(4)
    expect(graph.get_by_role("button", name="Select block 0x14000100F")).to_be_visible()

    original = graph.get_attribute("viewBox")
    page.get_by_role("button", name="Zoom in").click()
    assert graph.get_attribute("viewBox") != original
    page.get_by_role("button", name="Fit", exact=True).click()
    assert graph.get_attribute("viewBox") == original
    bounds = graph.bounding_box()
    page.mouse.move(bounds["x"] + 8, bounds["y"] + 8)
    page.mouse.down()
    page.mouse.move(bounds["x"] + 58, bounds["y"] + 48, steps=5)
    page.mouse.up()
    assert graph.get_attribute("viewBox") != original
    page.get_by_role("button", name="Fit", exact=True).click()

    graph.get_by_role("button", name="Select block 0x14000100F").click()
    expect(page.locator("#details")).to_contain_text("0x14000101B")
    graph.get_by_role("button", name="0x140001011", exact=False).click()
    expect(page.locator("#details")).to_contain_text("short")
    if screenshot:
        page.screenshot(path=str(screenshot))
    with page.expect_download() as download:
        page.get_by_role("button", name="Export CFG").click()
    exported = json.loads(Path(download.value.path()).read_text(encoding="utf-8"))
    assert len(exported["blocks"]) == 4
    assert any(e["kind"] == "branch_taken" and e["target"] == "0x14000101B" for e in exported["edges"])
    page.get_by_role("button", name="Show assembly").click()
    expect(page.locator("#details")).to_contain_text("0x140001011")

    page.locator("#details").get_by_role("button", name="References", exact=True).click()
    refs = page.get_by_role("table", name="References")
    expect(refs).to_contain_text("branch")
    page.get_by_label("Reference address").fill("0x140002000")
    page.get_by_role("button", name="Find references").click()
    expect(refs).to_contain_text("IP-relative")
    refs.get_by_role("button", name="0x140002000").click()
    expect(page.locator("#details")).to_contain_text(".rdata")

    page.get_by_role("button", name="Calls", exact=True).click()
    page.get_by_label("Call filter address").fill("0x140001024")
    page.get_by_role("button", name="Filter calls").click()
    calls = page.get_by_role("table", name="Calls")
    expect(calls).to_contain_text("0x14000100A")
    page.get_by_role("button", name="Call graph", exact=True).click()
    relationships = page.locator("#call-graph")
    expect(relationships).to_contain_text("Callers")
    relationships.get_by_role("button", name="0x140001000", exact=False).click()
    expect(relationships).to_contain_text("Callees")
    expect(relationships.get_by_role("button", name="0x140001024", exact=False)).to_be_visible()
    relationships.get_by_role("button", name="0x140001024", exact=False).click()
    page.get_by_role("button", name="Call graph", exact=True).click()
    calls.get_by_role("button", name="0x140001024").click()
    expect(graph.get_by_role("button", name="Select block 0x140001024")).to_be_visible()
    page.locator("#upload").set_input_files(str(ROOT / "tests" / "fixtures" / "branch.elf"))
    expect(page.get_by_role("heading", name="branch.elf")).to_be_visible()
    page.get_by_role("button", name="Functions", exact=True).click()
    expect(functions.get_by_role("button", name="0x401024")).to_be_visible()
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert not errors, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disecta", type=Path)
    parser.add_argument("--chrome", type=Path, help="Use the given Chrome instead of Playwright Chromium.")
    parser.add_argument("--screenshot", type=Path)
    args = parser.parse_args()
    server = subprocess.Popen([str(args.disecta.resolve(strict=True)), "gui"],
                              stdout=subprocess.PIPE, text=True)
    try:
        line = server.stdout.readline().strip()
        if not line.startswith("Open http://127.0.0.1:"):
            raise SystemExit(f"Unexpected workbench startup: {line}")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, executable_path=args.chrome)
            try:
                verify(browser.new_page(viewport={"width": 1440, "height": 900}), line[5:], args.screenshot)
            finally:
                browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    print("Phase A workbench checks passed.")


if __name__ == "__main__":
    main()
