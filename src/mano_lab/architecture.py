"""Evidence audit for Phase 1 development; never production execution authority."""

import hashlib
import json
import math
from pathlib import Path

SPEC_SHA256 = "6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace"
REQUIREMENTS = {
    "P0-01": ("debian-vm-4g", "btrfs-root-boot"),
    "P0-02": ("patched-packages", "protected-sentinels"),
    "P0-03": ("native-prompt-serial-rescue",),
    "P0-04": ("headless-sway-output", "headless-screenshot"),
    "P0-05": (
        "system-chromium-sandboxed-contract",
        "writer-sandboxed-document-contract",
        "chromium-libreoffice-isolated-input",
    ),
    "P0-06": ("atspi-named-save", "atspi-coordinate-action"),
    "P0-07": ("privileged-wayland-bind-denial", "xwayland-private-domain"),
    "P0-08": ("sandbox-kernel-denials",),
    "P0-09": ("request-bound-os-authenticated-approval",),
    "P0-10": ("native-independent-stop-and-revocation",),
    "P0-11": ("snapper-data-restore", "root-snapshot-boot-recovery"),
    "P0-12": ("cgroup-oom-contained", "measured-vm-resource-observations"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_hashes(root, report):
    root = root.resolve()
    for name, expected in report["artifact_sha256"].items():
        file = root / name
        resolved = file.resolve()
        require(
            resolved.is_relative_to(root) and file.is_file() and not file.is_symlink(),
            f"Invalid artifact path: {name}",
        )
        require(
            hashlib.sha256(file.read_bytes()).hexdigest() == expected, f"Artifact changed: {name}"
        )
    for probe in report["probes"]:
        if probe["status"] == "pass":
            require(bool(probe["artifacts"]), "Passing probe without artifacts")
            require(
                all(name in report["artifact_sha256"] for name in probe["artifacts"]),
                f"Unhashed evidence: {probe['name']}",
            )


def validate_startup(browser, office):
    for record, fields in (
        (
            browser,
            ("process_launch_to_control_ready_seconds", "process_launch_to_page_ready_seconds"),
        ),
        (office, ("process_launch_to_document_ready_seconds",)),
    ):
        require(
            isinstance(record, dict)
            and record.get("clock") == "monotonic"
            and record.get("cold_start_verified") is False,
            "Startup measurement missing or mis-scoped",
        )
        for field in fields:
            value = record.get(field)
            require(
                type(value) in {int, float} and math.isfinite(value) and value > 0,
                f"Missing or invalid startup measurement: {field}",
            )
    require(
        browser["process_launch_to_page_ready_seconds"]
        >= browser["process_launch_to_control_ready_seconds"],
        "Startup milestone order invalid",
    )


def audit(root: Path, spec: Path, adr: Path):
    report = json.loads((root / "report.json").read_text())
    require(
        hashlib.sha256(spec.read_bytes()).hexdigest() == SPEC_SHA256,
        "Original specification changed; repeat architecture review",
    )
    verify_hashes(root, report)
    first_report = json.loads((root / "first-root/report.json").read_text())
    verify_hashes(root / "first-root", first_report)
    for probe in first_report["probes"]:
        require(
            probe["status"] == "pass"
            or (probe["status"] == "pending" and probe["issue"] in {"P0-11", "P0-12"}),
            f"First-root probe failed/incomplete: {probe['name']}",
        )
    indexed = {p["name"]: p for p in report["probes"]}
    first_indexed = {p["name"]: p for p in first_report["probes"]}
    require(len(indexed) == len(report["probes"]), "Duplicate probe names")
    for probe in report["probes"]:
        require(
            probe["status"] == "pass"
            or (probe["name"] == "full-phase0-architecture-audit" and probe["status"] == "pending"),
            f"Incomplete or failed probe: {probe['name']}",
        )
    for issue, names in REQUIREMENTS.items():
        for name in names:
            require(
                name in indexed
                and indexed[name]["issue"] == issue
                and indexed[name]["status"] == "pass",
                f"Missing requirement: {issue}/{name}",
            )
            require(
                name in first_indexed
                and first_indexed[name]["issue"] == issue
                and (
                    first_indexed[name]["status"] == "pass"
                    or (
                        name == "root-snapshot-boot-recovery"
                        and first_indexed[name]["status"] == "pending"
                    )
                ),
                f"Missing requirement on first root: {issue}/{name}",
            )
    environment = report["environment"]
    require(
        environment["kind"] == "disposable-debian13-qemu"
        and environment["ram_ceiling_mib"] <= 8192
        and environment["physical_hardware"] is False
        and environment["agent_connected"] is False,
        "Unexpected evidence environment",
    )

    def load(name):
        require(name in report["artifact_sha256"], f"Unindexed audit evidence: {name}")
        return json.loads((root / name).read_text())

    wayland = load("wayland-confinement.json")
    require(
        wayland["ordinary_surface"] == "ordinary surface works"
        and wayland["trusted_bind_control"] == "bind succeeded"
        and wayland["listener_parent_write_denied"] is True
        and wayland["raw_socket_worker_exit"] != 0,
        "Wayland positive/negative controls failed",
    )
    attacks = wayland["attacks"]
    require(
        len(attacks) >= 16 and all(a["exit"] == 3 for a in attacks),
        "Privileged Wayland attack coverage incomplete",
    )
    attacked = {a["interface"] for a in attacks}
    require(
        {
            "zwp_virtual_keyboard_manager_v1",
            "zwlr_virtual_pointer_manager_v1",
            "zwlr_screencopy_manager_v1",
            "wp_security_context_manager_v1",
        }
        <= attacked,
        "Critical compositor protocols not attacked",
    )
    x11 = load("xwayland-confinement.json")
    require(
        all(
            x11[name] is True
            for name in (
                "authorized_x11_query",
                "missing_cookie_denied",
                "abstract_inside_positive_control",
                "abstract_namespace_denied",
                "other_principal_denied",
                "raw_wayland_human_ipc_hidden",
                "compositor_network_namespace_isolated",
            )
        )
        and bool(x11["mapped_x11_window"]),
        "XWayland boundary failed",
    )
    browser = load("browser-contract.json")
    require(
        browser["headless"] is False
        and browser["sandbox_requested"] is True
        and browser["renderer_seccomp_enforced"] is True
        and browser["locator_result"] == "clicked 1",
        "Browser contract incomplete",
    )
    office = load("office-contract.json")
    validate_startup(browser.get("startup"), office.get("startup"))
    validate_startup(
        json.loads((root / "first-root/browser-contract.json").read_text()).get("startup"),
        json.loads((root / "first-root/office-contract.json").read_text()).get("startup"),
    )
    require(
        office["named_action"]["name"] == "Save"
        and office["saved_text"] == office["pdf_text"]
        and {x["scale"] for x in office["scale_validation"]["scales"]} == {1, 2},
        "Office accessibility/coordinate evidence incomplete",
    )
    focus = load("cross-session-focus.json")
    require(
        focus["passed"] is True
        and not focus["violations"]
        and focus["samples"] > 0
        and focus["before"] == focus["after"]
        and focus["before"]["focused"] is True,
        "Human focus/text changed",
    )
    approval = load("authenticated-approval.json")
    require(
        approval["client"]["approval_outcomes"]
        == {
            "changed_operation": "binding-denied",
            "wrong_nonce": "binding-denied",
            "injected_target": "schema-denied",
            "expired": "expired-denied",
            "wrong_password": "auth-denied",
            "valid": "approved",
            "replay": "replay-denied",
        }
        and approval["client"]["tty"] == "/dev/ttyS0"
        and approval["physical_input_provenance"] is None
        and approval["production_broker"] is False,
        "OS-auth fallback not demonstrated",
    )
    require(
        len(approval["evidence"]["attacks"]["denials"]) == 9
        and approval["evidence"]["journal_owner_uid"] == 0
        and approval["evidence"]["journal_mode"] == "0600",
        "Approval boundary incomplete",
    )
    stop = load("independent-stop.json")
    require(
        stop["recovery_tty_usable"] is True and stop["physical_input_provenance"] is None,
        "Recovery/provenance boundary failed",
    )
    for phase in ("watchdog", "manual"):
        result = stop[phase]
        require(
            len(result["before"]["task_pids"]) >= 20
            and result["pulse_stopped"] is True
            and result["input_runtime_root_owned"] is True
            and result["epoch_after"] > result["before"]["grant"]["epoch"]
            and len(result["actor_denials"]) == 6
            and all(a["denied"] is True for a in result["actor_denials"])
            and result["core_after"]["state"] == "T (stopped)"
            and result["authority_after"]["state"] == "T (stopped)",
            "Independent stop failed",
        )
        limits = result["before"]["pids_limit_events_before"]
        require(
            len(limits) == 2 and all(int(v.split()[1]) > 0 for v in limits.values()),
            "Task pressure not kernel-limited",
        )
    grants = [g["result"] for g in stop["grant_checks"]]
    require(
        [g["decision"] for g in grants]
        == ["grant-valid", "revoked-denied", "grant-valid", "revoked-denied"]
        and grants[0]["use_count"] == grants[1]["use_count"]
        and grants[2]["use_count"] == grants[3]["use_count"],
        "Grant revocation failed",
    )
    serial = load("serial-rescue.json")
    require(
        serial["passed"] is True
        and serial["fixture_cleanup"]
        == {
            "account_locked": True,
            "core_removed": True,
        },
        "Serial fixture/recovery incomplete",
    )
    recovery = load("root-recovery.json")
    require(
        recovery["boot_id"] != recovery["source_boot_id"]
        and recovery["restored_sentinel"] == "before\n"
        and recovery["preserved_changed_root_sentinel"] == "after\n"
        and recovery["root_mount"]["filesystems"][0]["fsroot"] == "/@recovery",
        "Root recovery not demonstrated",
    )
    resources = load("resources.json")
    require(
        resources.get("app_startup_observations")
        == {
            "chromium": browser["startup"],
            "writer": office["startup"],
        },
        "Resource summary does not match measured app startup",
    )
    require(
        resources["physical_hardware"] is False
        and resources["model_connected"] is False
        and resources["pre_probe_guest_memory_bytes"]["MemTotal"] > 0
        and resources["sway_launch_to_output_seconds"] > 0,
        "Measurements not scoped",
    )
    preserved = (root / "bootstrap-preserved-before.sha256").read_bytes()
    require(
        preserved == (root / "bootstrap-preserved-after.sha256").read_bytes(),
        "Original bootstrap disk changed",
    )
    kernel = (root / "stop-kernel-journal.txt").read_text()
    require(
        "fork rejected" in kernel
        and not any(
            message in kernel
            for message in (
                "rcu_preempt kthread starved",
                "rcu: INFO:",
                "soft lockup",
                "BUG:",
            )
        ),
        "Pressure kernel journal missing or contains a stall",
    )
    return {
        "decision": "go-for-phase1-development",
        "spec_sha256": SPEC_SHA256,
        "adr_sha256": hashlib.sha256(adr.read_bytes()).hexdigest(),
        "requirements": {issue: list(names) for issue, names in REQUIREMENTS.items()},
        "verified_artifact_sha256": report["artifact_sha256"],
        "first_root_artifact_sha256": first_report["artifact_sha256"],
        "approval_strategy": "request-bound OS-authenticated ttyS0 fallback",
        "production_execution_authorized": False,
        "physical_input_provenance": None,
        "bootstrap_preserved_hash_record": preserved.decode().strip(),
        "pressure_kernel_journal_sha256": hashlib.sha256(kernel.encode()).hexdigest(),
        "app_startup_observations": resources["app_startup_observations"],
        "deferred_release_gates": environment["deferred_release_gates"],
    }
