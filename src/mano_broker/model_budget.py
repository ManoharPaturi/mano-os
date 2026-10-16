"""Trusted task budget accounting. Amounts are integer micro-USD, never floats.

This ledger does not establish provider prices or tokenize requests. A trusted
executor must supply a conservative reservation before any paid dispatch.
"""

import json
import math

from .protocol import identifier
from .state import Denied

MAX_AMOUNT = 10**12
MAX_TOKENS = 10**9


def bounded(value, maximum, *, zero=False):
    if type(value) is not int or not (0 if zero else 1) <= value <= maximum:
        raise ValueError('Invalid integer model budget')
    return value


class ModelBudget:
    def __init__(self, state):
        self.state = state

    def configure(self, task_id, *, authenticated_human_uid, boot_id, money, tokens):
        """Trusted approval only; initial limits are immutable in this revision."""
        identifier(task_id)
        bounded(money, MAX_AMOUNT)
        bounded(tokens, MAX_TOKENS)
        with self.state.transaction():
            task = self.state.db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
            if (task is None or type(authenticated_human_uid) is not int
                    or task['human_uid'] != authenticated_human_uid or task['boot_id'] != boot_id
                    or self.state.meta('latched')):
                raise Denied('No authenticated task budget authority')
            if self.state.db.execute('SELECT 1 FROM model_budgets WHERE task_id=?',
                                     (task_id,)).fetchone():
                raise Denied('Task budget cannot be replaced or increased')
            self.state.db.execute('INSERT INTO model_budgets VALUES(?,?,?)',
                                  (task_id, money, tokens))
            self.state.event(None, 'model-budget-approved', dict(task_id=task_id,
                money_micro_usd=money, tokens=tokens))

    def apply_grant(self, grant_id, *, now, boot_id):
        """Consume a dedicated exact budget grant inside authenticated approval."""
        identifier(grant_id)
        if type(now) not in {int, float} or not math.isfinite(now) or now < 0:
            raise ValueError('Invalid trusted budget clock')
        with self.state.transaction():
            grant = self.state.db.execute('SELECT g.*,t.boot_id,t.human_uid AS task_human,'
                't.resource_id AS task_resource '
                'FROM grants g JOIN tasks t ON g.task_id=t.id WHERE g.id=?',
                (grant_id,)).fetchone()
            if (grant is None or grant['capability'] != 'model.set_budget'
                    or grant['human_uid'] != grant['task_human'] or grant['boot_id'] != boot_id
                    or grant['resource_id'] != grant['task_resource']
                    or self.state.meta('latched') or grant['revoked']
                    or grant['epoch'] != self.state.meta('epoch') or now >= grant['expires']
                    or grant['used'] != 0 or grant['max_count'] != 1):
                raise Denied('No unused authenticated model budget grant')
            args = json.loads(grant['approved_args_json'])
            if set(args) != {'money_micro_usd', 'tokens'}:
                raise Denied('Invalid exact model budget grant')
            money = bounded(args['money_micro_usd'], MAX_AMOUNT)
            tokens = bounded(args['tokens'], MAX_TOKENS)
            prior = self.state.db.execute('SELECT * FROM model_budgets WHERE task_id=?',
                                         (grant['task_id'],)).fetchone()
            if prior and (money < prior['money_limit'] or tokens < prior['token_limit']):
                raise Denied('Budget grants cannot silently lower existing task limits')
            self.state.db.execute('INSERT INTO model_budgets VALUES(?,?,?) '
                'ON CONFLICT(task_id) DO UPDATE SET money_limit=excluded.money_limit,'
                'token_limit=excluded.token_limit', (grant['task_id'], money, tokens))
            self.state.db.execute('UPDATE grants SET used=1 WHERE id=?', (grant_id,))
            self.state.event(None, 'model-budget-grant-consumed', dict(grant_id=grant_id,
                task_id=grant['task_id'], money_micro_usd=money, tokens=tokens))

    def reserve(self, action_id, *, boot_id, money, tokens):
        """Caller composes this with ModelStore.begin in one outer transaction."""
        from .models import ModelStore

        bounded(money, MAX_AMOUNT)
        bounded(tokens, MAX_TOKENS)
        with self.state.transaction():
            action, _ = ModelStore(self.state).action(action_id, boot_id)
            if action['state'] != 'intent' or self.state.meta('latched'):
                raise Denied('Model budget reservation requires an original intent')
            if self.state.db.execute('SELECT 1 FROM model_reservations WHERE action_id=?',
                                     (action_id,)).fetchone():
                raise Denied('Paid attempt already reserved')
            limit = self.state.db.execute('SELECT * FROM model_budgets WHERE task_id=?',
                                         (action['task_id'],)).fetchone()
            used = self.state.db.execute('SELECT coalesce(sum(money),0),coalesce(sum(tokens),0) '
                'FROM model_reservations WHERE task_id=?', (action['task_id'],)).fetchone()
            if limit is None or used[0] + money > limit['money_limit'] \
                    or used[1] + tokens > limit['token_limit']:
                raise Denied('Task model budget exhausted or absent')
            self.state.db.execute('INSERT INTO model_reservations VALUES(?,?,?,?,0)',
                                  (action_id, action['task_id'], money, tokens))
            self.state.event(action_id, 'model-budget-reserved',
                             dict(money_micro_usd=money, tokens=tokens))

    def begin(self, action_id, *, now, boot_id, money, tokens):
        from .models import ModelStore

        with self.state.transaction():
            self.reserve(action_id, boot_id=boot_id, money=money, tokens=tokens)
            return ModelStore(self.state).begin(action_id, now=now, boot_id=boot_id)

    def settle(self, action_id, *, boot_id, money, tokens):
        """Trusted measured billing only; unknown effects retain the full reserve."""
        from .models import ModelStore

        bounded(money, MAX_AMOUNT, zero=True)
        bounded(tokens, MAX_TOKENS, zero=True)
        with self.state.transaction():
            action, _ = ModelStore(self.state).action(action_id, boot_id)
            row = self.state.db.execute('SELECT * FROM model_reservations WHERE action_id=?',
                                       (action_id,)).fetchone()
            if (row is None or row['settled'] or action['state'] != 'done'
                    or row['task_id'] != action['task_id']
                    or money > row['money'] or tokens > row['tokens']):
                raise Denied('No completed bounded model bill to settle')
            task = self.state.db.execute('SELECT caller_uid FROM tasks WHERE id=?',
                                         (action['task_id'],)).fetchone()
            result = ModelStore(self.state).read(action_id, task_id=action['task_id'],
                caller_uid=task['caller_uid'], boot_id=boot_id)
            if tokens != result['usage']['total_tokens']:
                raise Denied('Settlement tokens disagree with durable provider usage')
            self.state.db.execute('UPDATE model_reservations SET money=?,tokens=?,settled=1 '
                                  'WHERE action_id=?', (money, tokens, action_id))
            self.state.event(action_id, 'model-budget-settled',
                             dict(money_micro_usd=money, tokens=tokens))
