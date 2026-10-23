# Live APT package marks must match the approved catalog

APT extended_states records which packages were installed automatically. These
marks are solver inputs even when the installed package status does not change.
A catalog copied them previously but checked only live dpkg status, signed index
identities and Debian trust anchors. A changed mark could therefore leave an old
forecast apparently current.

Catalog creation now captures the bounded, trusted fixed-path marks and records
their presence, byte length and SHA256 in the catalog identity. Absence differs
from an empty file. It rechecks the source before publishing. Current catalog
admission compares the live marks and their copied-input metadata with that
identity. Missing legacy metadata requires an explicit catalog refresh. Symlinks,
untrusted custody and oversized inputs retain the existing rejection rules.

Every existing catalog admission point inherits this check: forecast approval,
installation review, independent locked Root resolution, and sealed archive
custody. It grants no new authority and performs no package installation.

Local tests cover changes with unchanged dpkg status, absence, dangling links and
absent/empty identity. The disposable Debian CI changes only the live marks,
requires catalog and locked Root admission to reject the old plan, then restores
the original bytes and requires the same plan to resolve again. Evidence is
package_plans.dependency-plan.root_resolution.changed_live_apt_marks_denied and
restored_live_apt_marks_admitted in the security report. Native evidence is
pending until the exact-head CI run and artifact are accepted.
