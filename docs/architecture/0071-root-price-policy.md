# Root-provisioned broker price policy

The provider socket client no longer accepts a caller-supplied PricePolicy. It
loads only the fixed pricing credential in
/run/credentials/mano-broker.service under the separate unprivileged broker UID.
Root-owned ancestors, pinned no-follow directory/file descriptors, private modes
or the exact named-service read ACL, single link and a4096-byte bound are required.
The file contains only strict provider/enable/schema/price metadata, never an API
key. Model, revision, numeric bounds and price freshness are validated before any
attempt reservation. Wrong identity/path, malformed or disabled policy denies.

mano-broker.service receives pricing through LoadCredential from
/etc/mano/pricing.json. Linux packaging/migration must install the shipped disabled
packaging/config/pricing.json as root:root0600 before starting the unit, only if
no configuration exists; never overwrite an operator's existing policy with the
default. Root configuration changes take effect on service restart, not through
caller environment, wire fields or a mutable policy object. Restart still invokes
the existing unknown-effect/grant revocation recovery rules.

The existing pinned credential-file reader is shared by both roles; each role
keeps its own fixed directory/name/identity checks. Provider key permissions and
paths are unchanged. The guarded VM checks the loaded disabled pricing policy
under the broker UID in its unit mount namespace, then edits the root source and
checks that the already-loaded snapshot remains disabled. Required final flags:
installed_broker_disabled_price_policy and
loaded_broker_price_policy_immutable_snapshot. Until final CI, that installed
snapshot evidence is pending. No host namespaces or services are modified.

All rates in tests are synthetic. This does not verify a real model's pricing,
context or billing. Default pricing and provider generation remain disabled;
verified provisioning, permitted fixed egress and installed/live execution gates
remain. An operator must supply independently verified current metadata before
any future paid activation.
