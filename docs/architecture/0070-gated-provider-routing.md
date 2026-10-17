# Policy-gated protected provider routing

The protected one-request service now distinguishes health and generation packets.
Health keeps its existing behavior. Generation authenticates the broker before
policy access, loads and validates policy without opening the key, and checks the
original request/current boot/deadlines before key loading. The execute helper
rechecks with fresh clocks after key loading and performs one fixed invocation
and sealed reply. Success sends no extra plain JSON packet. Errors remain fixed
nonsecret denials; no exception text or credentials are returned or logged.

Default policy is disabled, and the installed unit still uses PrivateNetwork=yes
and RestrictAddressFamilies=AF_UNIX. This PR does not provision an API key, enable
public broker model execution, relax egress or claim paid generation. A root policy
flag alone is insufficient for usable generation under this network profile.

Unit tests check denied actors, disabled/malformed jobs before key read, credential
loading order and exactly one response path. The guarded VM witness requires
installed_provider_disabled_generation_denied in addition to health/deadline/Stop
proof. Successful generation remains a component test with mocked HTTPS, not an
installed network or live billing claim. Before activation, verify provisioning,
allowed egress, the complete installed executor route and native cancellation,
and real API/billing behavior.
