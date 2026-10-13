# Default prompt production submission witness

The installed VM now constructs the actual Prompt GTK application under the
configured human UID with no injected local recorder, calls its default submit
handler, and requires a protected native received acknowledgement plus matching
native status. No task/action is created by this intent-only receipt.

This verifies production handler wiring and actual human-channel transport rather
than the Phase0 local-data callback. It does not claim a physical keyboard click,
rendered default-window/native-server interaction or end-to-end real-model dispatch.
The separate Phase0 layout/focus canary remains explicitly recorder-backed. Actual
native actor/malformed/idempotence and full factory/core/security cases remain in CI.
The new flag is emitted only if the installed VM witness and all prior gates pass.
