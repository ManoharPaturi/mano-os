"""Fixed initial workspace profile bounds, included in the exact PAM approval."""


def configuration(args):
    if not isinstance(args, dict) or set(args) != {
            'mode', 'duration_seconds', 'max_actions', 'max_timeout_seconds'}:
        raise ValueError('Unexpected permission profile fields')
    mode = args['mode']
    if not isinstance(mode, str) or mode not in {'supervised', 'auto', 'full-access'}:
        raise ValueError('Unknown permission profile')
    maximum = 300 if mode == 'full-access' else 900
    for key, ceiling in (('duration_seconds', maximum), ('max_actions', 32),
                         ('max_timeout_seconds', 300)):
        if type(args[key]) is not int or not 1 <= args[key] <= ceiling:
            raise ValueError('Invalid bounded permission profile')
    return dict(args)


AUTO_TOOLS = frozenset({'/usr/bin/python3', '/usr/bin/git', '/usr/bin/make',
                        '/usr/bin/node', '/usr/bin/pytest'})


def scope(mode):
    return dict(filesystem='allocated task workspace only', network='disabled',
        automatic_capabilities=(['system.inspect_health', 'files.read'] if mode == 'supervised'
            else ['system.inspect_health', 'files.read', 'files.write', 'terminal.run']),
        terminal_entrypoints=([] if mode == 'supervised' else sorted(AUTO_TOOLS) if mode == 'auto'
            else ['/usr/bin/*', '/bin/*', '/workspace/*']),
        entrypoint_policy='admission only; child execution remains inside the same sandbox',
        model_disclosure='separate approval', model_budget='separate approval',
        expiry='blocks new authorization/dispatch; running actions retain their runtime limit')
