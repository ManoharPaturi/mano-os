"""Pinned optional coding delegates; fixed public argv shapes, no authority."""

from .actions import model_identifier, text

VERSIONS = {'antigravity': '1.4.2', 'codex': '0.163.0'}
EXECUTABLES = {
    'antigravity': '/usr/lib/mano-delegates/antigravity-1.4.2/agy',
    'codex': '/usr/lib/mano-delegates/codex-0.163.0/codex/codex',
}


def command(name, operation, *, prompt=None, model=None):
    if name not in VERSIONS:
        raise ValueError('Unknown pinned coding delegate')
    executable = EXECUTABLES[name]
    if operation in {'version', 'help'}:
        if prompt is not None or model is not None:
            raise ValueError('Contract inspection accepts no prompt or model')
        return [executable, '--' + operation]
    if operation != 'run':
        raise ValueError('Unknown delegate operation')
    text(prompt, 2048)
    model_identifier(model)
    if name == 'antigravity':
        return [executable, '--prompt=' + prompt, '--output-format', 'stream-json',
                '--print-timeout=10s', '--model=' + model]
    return [executable, 'exec', '--json', '--ephemeral', '--sandbox', 'workspace-write',
            '--color', 'never', '--skip-git-repo-check', '--model=' + model, '--', prompt]


def identify(argv):
    if not isinstance(argv, list) or not argv or argv[0] not in EXECUTABLES.values():
        return None
    if any(not isinstance(item, str) for item in argv):
        raise ValueError('Delegate arguments must be strings')
    name = next(k for k, value in EXECUTABLES.items() if value == argv[0])
    for operation in ('version', 'help'):
        if argv == command(name, operation):
            return name
    try:
        if name == 'antigravity':
            expected = command(name, 'run', prompt=argv[1].removeprefix('--prompt='),
                               model=argv[-1].removeprefix('--model='))
        else:
            expected = command(name, 'run', prompt=argv[-1],
                               model=argv[-3].removeprefix('--model='))
    except (ValueError, IndexError, TypeError):
        raise ValueError('Invalid fixed delegate invocation') from None
    if argv != expected:
        raise ValueError('Unsupported delegate flags or scope')
    return name
