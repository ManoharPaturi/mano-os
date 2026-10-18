"""PAM-origin, time/count bounded workspace authority; never a sandbox bypass."""

import json
from pathlib import PurePosixPath

from mano_protocol.profiles import AUTO_TOOLS, configuration

from .approvals import clock
from .protocol import Capability, canonical, identifier
from .state import Denied

READ_ONLY = frozenset({Capability.READ, Capability.INSPECT})
WORKSPACE = READ_ONLY | {Capability.WRITE, Capability.RUN}


class Profiles:
    def __init__(self, state):
        self.state = state

    def apply_grant(self, grant_id, *, approval_id, now, boot_id):
        clock(now)
        identifier(grant_id)
        identifier(approval_id)
        with self.state.transaction():
            grant = self.state.db.execute('SELECT g.*,t.boot_id,t.human_uid AS task_human,'
                't.resource_id AS task_resource FROM grants g JOIN tasks t ON g.task_id=t.id '
                'WHERE g.id=?', (grant_id,)).fetchone()
            generation = self.state.db.execute(
                "SELECT value FROM meta WHERE key='native_generation'").fetchone()
            if (grant is None or grant['capability'] != 'policy.set_profile'
                    or grant['human_uid'] != grant['task_human'] or grant['boot_id'] != boot_id
                    or grant['resource_id'] != grant['task_resource']
                    or self.state.meta('latched') or grant['revoked']
                    or grant['epoch'] != self.state.meta('epoch') or now >= grant['expires']
                    or grant['used'] != 0 or grant['max_count'] != 1 or generation is None
                    or generation[0] < 0 or grant['native_generation'] != generation[0]):
                raise Denied('No unused authenticated permission profile grant')
            approval = self.state.db.execute('SELECT * FROM approvals WHERE id=?',
                                             (approval_id,)).fetchone()
            if (approval is None or approval['state'] != 'pending'
                    or approval['task_id'] != grant['task_id']):
                raise Denied('Profile requires its original pending PAM approval')
            view = json.loads(approval['view_json'])
            if (view['capability'] != 'policy.set_profile'
                    or canonical(view['args']) != grant['approved_args_json']):
                raise Denied('Profile approval arguments changed')
            if self.state.db.execute("SELECT 1 FROM actions WHERE task_id=? AND state='executing'",
                                     (grant['task_id'],)).fetchone():
                raise Denied('Profile changes require an idle task; Stop is independent')
            args = configuration(json.loads(grant['approved_args_json']))
            self.state.db.execute('UPDATE grants SET revoked=1 WHERE id IN '
                '(SELECT grant_id FROM profile_grants WHERE source_grant_id IN '
                '(SELECT grant_id FROM task_profiles WHERE task_id=?))', (grant['task_id'],))
            self.state.db.execute('INSERT INTO task_profiles VALUES(?,?,?,?,?,?,?,?,?,?) '
                'ON CONFLICT(task_id) DO UPDATE SET grant_id=excluded.grant_id,'
                'approval_id=excluded.approval_id,mode=excluded.mode,expires=excluded.expires,'
                'remaining=excluded.remaining,max_timeout=excluded.max_timeout,'
                'boot_id=excluded.boot_id,epoch=excluded.epoch,generation=excluded.generation',
                (grant['task_id'], grant_id, approval_id, args['mode'],
                 now + args['duration_seconds'], args['max_actions'], args['max_timeout_seconds'],
                 boot_id, grant['epoch'], generation[0]))
            self.state.db.execute('UPDATE grants SET used=1 WHERE id=?', (grant_id,))
            self.state.db.execute('UPDATE tasks SET mode=? WHERE id=?',
                                  (args['mode'], grant['task_id']))
            self.state.event(None, 'permission-profile-approved', dict(task_id=grant['task_id'],
                approval_id=approval_id, grant_id=grant_id, **args))

    def require_grant(self, grant_id, *, now, boot_id):
        origin = self.state.db.execute(
            'SELECT source_grant_id FROM profile_grants WHERE grant_id=?', (grant_id,)).fetchone()
        if origin is None:
            return
        row = self.state.db.execute('SELECT p.*,g.revoked,g.used,t.mode AS task_mode '
            'FROM task_profiles p JOIN grants g ON p.grant_id=g.id '
            'JOIN tasks t ON p.task_id=t.id WHERE p.grant_id=?', (origin[0],)).fetchone()
        generation = self.state.db.execute(
            "SELECT value FROM meta WHERE key='native_generation'").fetchone()
        if (row is None or row['revoked'] or row['used'] != 1 or self.state.meta('latched')
                or row['epoch'] != self.state.meta('epoch') or now >= row['expires']
                or row['boot_id'] != boot_id or row['mode'] != row['task_mode']
                or generation is None or row['generation'] != generation[0]):
            raise Denied('Permission profile provenance expired or revoked')

    def maybe_issue(self, approval_id, request, task, *, now, boot_id):
        clock(now)
        with self.state.transaction():
            row = self.state.db.execute('SELECT p.*,g.revoked,g.used FROM task_profiles p '
                'JOIN grants g ON p.grant_id=g.id WHERE p.task_id=?', (task['id'],)).fetchone()
            generation = self.state.db.execute(
                "SELECT value FROM meta WHERE key='native_generation'").fetchone()
            if (row is None or row['revoked'] or row['used'] != 1 or row['remaining'] <= 0
                    or now >= row['expires'] or self.state.meta('latched')
                    or row['epoch'] != self.state.meta('epoch') or row['boot_id'] != boot_id
                    or generation is None or row['generation'] != generation[0]
                    or task['mode'] != row['mode']):
                return None
            permitted = READ_ONLY if row['mode'] == 'supervised' else WORKSPACE
            if request.capability not in permitted:
                return None  # Profile/budget/model disclosure can NEVER approve themselves.
            args = json.loads(request.args_json)
            if request.capability == Capability.RUN:
                if args['timeout_seconds'] > row['max_timeout']:
                    return None
                program = args['argv'][0]
                if row['mode'] == 'auto' and program not in AUTO_TOOLS:
                    return None
                if row['mode'] == 'full-access':
                    path = PurePosixPath(program)
                    if (not path.is_absolute() or '..' in path.parts
                            or not any(path.is_relative_to(base)
                                       for base in ('/usr/bin', '/bin', '/workspace'))):
                        return None
            grant_id = self.state.issue_grant(task['id'], approved_human_uid=task['human_uid'],
                approved_args=args, capability=request.capability, resource_id=task['resource_id'],
                expires=min(now + 60, row['expires']), max_count=1,
                memory_bytes=256*1024**2, pids=32, cpu_percent=20,
                max_timeout_seconds=row['max_timeout'])
            self.state.db.execute('INSERT INTO profile_grants VALUES(?,?)',
                                  (grant_id, row['grant_id']))
            self.state.db.execute('UPDATE task_profiles SET remaining=remaining-1 WHERE task_id=?',
                                  (task['id'],))
            self.state.db.execute("UPDATE approvals SET state='approved',grant_id=? WHERE id=?",
                                  (grant_id, approval_id))
            self.state.event(None, 'permission-profile-grant-issued', dict(task_id=task['id'],
                approval_id=approval_id, grant_id=grant_id, source_approval_id=row['approval_id']))
            return grant_id
