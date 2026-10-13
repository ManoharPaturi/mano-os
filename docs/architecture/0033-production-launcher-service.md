# Production launcher entry point

mano_broker.launcher_service accepts only the two fixed activated listeners and
no CLI paths, commands or configuration. It creates the delegated Manager and
private Controller, gives control traffic priority over preparation, enforces
independent connection budgets, and sweeps child/owner lifetimes on every loop.
Disconnecting before a reply does not crash the daemon; prepared work remains
subject to its existing owner pidfd and TTL. Systemd owns socket permissions.

The packaged unit retains the measured SETUID/SETGID capability boundary and
ambient SETUID needed for the transition, NNP, root-protected code, private tmp/
devices and strict filesystem protection. Delegate is limited to CPU/memory/PIDs.
KillMode=control-group and five-second stop timeout cover service termination.
No unit is installed or started on the user's Mac.

The disposable-VM probe first runs earlier cgroup/transport/journal cases, stops
that fixture, replaces its temporary unit with the exact packaged service/socket
files, starts the production module and runs a persistent broker UID client with
real journal/Registry/executor. It checks completion/output and journal Stop
cancellation. Broker journals are outside task workspaces in the broker-private
/run/mano-journal-ci fixture root. All temporary units/accounts/workspaces are
removed only after services stop. Production daemon evidence is pending CI.

This entry point still trusts the authenticated broker's Start assertion. Public
Runtime/PAM-authorized execution integration, resource-limit selection and native
Stop independent of a frozen broker remain required. Operator-issued grants in
this probe do not authenticate a human or verify task artifacts.
