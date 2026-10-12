"""Real Writer/UNO/AT-SPI contract on a private task bus in the CI guest."""

import json
import os
import subprocess
import time
import zipfile
from pathlib import Path

import dbus
import uno
from com.sun.star.beans import PropertyValue

ROOT = Path("/workspace")
BEFORE = "mano document before named save"
AFTER = "mano document saved through accessibility"


def properties(**values):
    result = []
    for key, value in values.items():
        item = PropertyValue()
        item.Name, item.Value = key, value
        result.append(item)
    return tuple(result)


def descendants(node, depth=0):
    if depth > 12:
        return
    yield node
    for index in range(min(node.childCount, 400)):
        try:
            yield from descendants(node.getChildAtIndex(index), depth + 1)
        except Exception:
            continue


def wait_file(name, timeout=20):
    deadline = time.monotonic() + timeout
    while not (ROOT / name).is_file():
        if time.monotonic() > deadline:
            raise RuntimeError(f"Timed out waiting for {name}")
        time.sleep(0.1)
    return json.loads((ROOT / name).read_text())


def geometry_contract(document, pyatspi):
    # Keep the original contract.odt/PDF unchanged for the semantic-action evidence.
    document.storeAsURL("file:///workspace/geometry.odt", properties(FilterName="writer8"))
    results = []
    for scale in (1, 2):
        config = wait_file(f"geometry-config-{scale}.json")
        assert config["scale"] == scale
        expected = f"mano coordinate save at scale {scale}"
        document.Text.String = expected
        assert document.isModified()
        deadline = time.monotonic() + 15
        target = None
        while time.monotonic() < deadline:
            inventory = []
            for node in descendants(pyatspi.Registry.getDesktop(0)):
                try:
                    name, role = node.name or "", node.getRoleName()
                    states = node.getState()
                    entry = {"name": name, "role": role}
                    inventory.append(entry)
                    if (
                        role not in {"button", "push button"}
                        or name.split("(")[0].strip() != "Save"
                    ):
                        continue
                    if not all(
                        states.contains(flag)
                        for flag in (
                            pyatspi.STATE_SHOWING,
                            pyatspi.STATE_VISIBLE,
                            pyatspi.STATE_ENABLED,
                        )
                    ):
                        continue
                    bounds = node.queryComponent().getExtents(pyatspi.WINDOW_COORDS)
                    rect = [bounds.x, bounds.y, bounds.width, bounds.height]
                    entry["window_bounds"] = rect
                    if min(rect[:2]) < 0 or min(rect[2:]) < 5:
                        continue
                    if (
                        bounds.x + bounds.width > config["client_size"][0]
                        or bounds.y + bounds.height > config["client_size"][1]
                    ):
                        continue
                    target = dict(entry, visible=True, showing=True, enabled=True)
                    break
                except (NotImplementedError, LookupError):
                    continue
            (ROOT / f"geometry-tree-{scale}.json").write_text(
                json.dumps(inventory, indent=2) + "\n"
            )
            if target:
                break
            time.sleep(0.1)
        assert target, "No visible Save button with usable window-relative geometry"
        # No semantic Save is invoked below: only the protected controller clicks.
        (ROOT / f"geometry-target-{scale}.json").write_text(json.dumps(target, indent=2) + "\n")
        click = wait_file(f"geometry-click-{scale}.json")
        deadline = time.monotonic() + 10
        while document.isModified() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not document.isModified(), "Coordinate click did not save Writer document"
        with zipfile.ZipFile(ROOT / "geometry.odt") as archive:
            assert expected in archive.read("content.xml").decode()
        result = {
            "scale": scale,
            "target": target,
            "controller": click,
            "saved_text": expected,
            "saved_by_coordinate_click": True,
        }
        results.append(result)
        (ROOT / f"geometry-result-{scale}.json").write_text(json.dumps(result, indent=2) + "\n")
    report = {
        "scales": results,
        "coordinate_space": "window logical -> compositor logical -> output pixels",
        "physical_input_provenance": None,
        "production_executor": False,
    }
    (ROOT / "office-geometry.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    # D-Bus was created inside this sandbox, not imported from either host session.
    assert os.environ["DBUS_SESSION_BUS_ADDRESS"].startswith("unix:")
    assert not Path("/run/mano-human").exists()
    assert not Path("/run/mano-agent").exists()
    bus = dbus.SessionBus()
    status = bus.get_object("org.a11y.Bus", "/org/a11y/bus")
    dbus.Interface(status, "org.freedesktop.DBus.Properties").Set(
        "org.a11y.Status", "IsEnabled", dbus.Boolean(True)
    )
    import pyatspi

    env = dict(os.environ, SAL_USE_VCLPLUGIN="gtk3", SAL_ACCESSIBILITY_ENABLED="1")
    log = (ROOT / "office-process.txt").open("w")
    proc = subprocess.Popen(
        [
            "/usr/bin/libreoffice",
            "--writer",
            "--nologo",
            "--norestore",
            "--nodefault",
            "--nofirststartwizard",
            "-env:UserInstallation=file:///workspace/office-profile",
            "--accept=pipe,name=mano-office;urp;StarOffice.ComponentContext",
        ],
        env=env,
        stdout=log,
        stderr=log,
    )
    document = None
    try:
        local = uno.getComponentContext()
        resolver = local.ServiceManager.createInstanceWithContext(
            "com.sun.star.bridge.UnoUrlResolver", local
        )
        deadline = time.monotonic() + 30
        while True:
            try:
                remote = resolver.resolve(
                    "uno:pipe,name=mano-office;urp;StarOffice.ComponentContext"
                )
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise RuntimeError("Writer UNO pipe timed out") from None
                time.sleep(0.2)
        desktop = remote.ServiceManager.createInstanceWithContext(
            "com.sun.star.frame.Desktop", remote
        )
        document = desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())
        document.Text.String = BEFORE
        document.storeAsURL("file:///workspace/contract.odt", properties(FilterName="writer8"))
        document.Text.String = AFTER
        assert document.isModified()
        saved_action = None
        inventory = []
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            inventory = []
            for node in descendants(pyatspi.Registry.getDesktop(0)):
                try:
                    entry = {"name": node.name, "role": node.getRoleName()}
                    try:
                        action = node.queryAction()
                        entry["actions"] = [action.getName(i) for i in range(action.nActions)]
                    except NotImplementedError:
                        entry["actions"] = []
                    inventory.append(entry)
                    if (
                        node.name == "Save"
                        and entry["actions"]
                        and node.getState().contains(pyatspi.STATE_ENABLED)
                    ):
                        bounds = node.queryComponent().getExtents(pyatspi.DESKTOP_COORDS)
                        assert action.doAction(0), "Named Save action rejected"
                        saved_action = dict(
                            entry,
                            bounds=[bounds.x, bounds.y, bounds.width, bounds.height],
                            bounds_usable=(
                                bounds.x != -(2**31)
                                and bounds.y != -(2**31)
                                and bounds.width > 0
                                and bounds.height > 0
                            ),
                        )
                        break
                except (NotImplementedError, LookupError):
                    continue
            (ROOT / "office-accessibility-tree.json").write_text(
                json.dumps(inventory, indent=2) + "\n"
            )
            if saved_action:
                break
            time.sleep(0.2)
        assert saved_action, "No enabled named Save action in the real accessibility tree"
        deadline = time.monotonic() + 10
        while document.isModified() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not document.isModified(), "Accessible Save did not store the document"
        with zipfile.ZipFile(ROOT / "contract.odt") as archive:
            xml = archive.read("content.xml").decode()
        assert AFTER in xml and BEFORE not in xml
        document.storeToURL(
            "file:///workspace/contract.pdf", properties(FilterName="writer_pdf_Export")
        )
        pdf_text = subprocess.check_output(
            ["pdftotext", str(ROOT / "contract.pdf"), "-"], text=True
        )
        assert AFTER in pdf_text
        report = {
            "version": subprocess.check_output(["libreoffice", "--version"], text=True).strip(),
            "backend": "gtk3 Wayland",
            "uno_transport": "task-private pipe",
            "session_bus": os.environ["DBUS_SESSION_BUS_ADDRESS"],
            "a11y_bus": str(dbus.Interface(status, "org.a11y.Bus").GetAddress()),
            "named_action": saved_action,
            "saved_text": AFTER,
            "pdf_text": pdf_text.strip(),
            "physical_input_provenance": None,
            "scale_validation": None,
        }
        (ROOT / "office-ready.json").write_text(json.dumps(report, indent=2) + "\n")
        deadline = time.monotonic() + 20
        while not (ROOT / "office-observer-done").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("Independent office observer timed out")
            time.sleep(0.1)
        report["scale_validation"] = geometry_contract(document, pyatspi)
        (ROOT / "office-contract.json").write_text(json.dumps(report, indent=2) + "\n")
    finally:
        if document is not None:
            document.close(True)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()


if __name__ == "__main__":
    main()
