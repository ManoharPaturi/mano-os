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
