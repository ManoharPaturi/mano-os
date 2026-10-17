# Installed core entry point for broker-backed planning

Both core and Root lifecycle commands now require an explicit mutually exclusive
--mock or --broker-model mode. Broker mode accepts only fixed managed context and
model/max-output metadata. It accepts no API key, URL, provider transport, supplied
terminal plan or grant authority. The same managed task identity, cgroup, resource
limits, no-capability profile, AF_UNIX restriction and native Stop checks apply.

The core constructs BrokerPlanner and uses the existing private SQLite Session.
Its first step requests disclosure approval for the exact original human prompt.
Later bounded steps reconcile the original model action and saved broker result;
a returned terminal plan requests a separate approval. Neither the core nor Root
lifecycle treats a model response or child exit as execution verification.

Root accepts only bounded pending states when no terminal action exists. Once an
action is present, it strictly validates the returned terminal proposal's original
task/resource/operation, then compares its digest against the protected broker
journal and uses that journal's state and independent verification flag. A forged
core completion or different proposal cannot become a verified result.

The guarded Debian probe invokes the actual installed Root lifecycle CLI twice in
broker mode for a separate logical operation in a managed task. It checks a saved
awaiting_model_grant status, one disclosure approval, no model grants and no provider
jobs. Required witness: installed_broker_planner_core_entrypoint. This proves the
installed constrained core entry point, broker transport and checkpoint reopen;
it does not prove approved provider execution or a recurring controller service.
Root pricing and provider generation remain disabled, no Internet is enabled,
and synthetic model metadata in CI is not a billing or model-availability claim.
