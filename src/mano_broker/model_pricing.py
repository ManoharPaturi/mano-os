"""Trusted configured price ceilings; no price discovery, network or credentials."""

import json
from dataclasses import asdict, dataclass

from mano_protocol.actions import canonical, model_identifier

from .model_budget import MAX_AMOUNT, MAX_TOKENS, ModelBudget, bounded
from .models import ModelStore
from .state import Denied


@dataclass(frozen=True)
class PricePolicy:
    model: str
    revision: str
    expires_unix: int
    input_context_tokens: int
    max_output_tokens: int
    input_micro_usd_per_million: int
    output_micro_usd_per_million: int

    def quote(self, args, *, wall_time):
        model_identifier(self.model)
        model_identifier(self.revision)
        bounded(self.expires_unix, 2**53)
        bounded(wall_time, 2**53, zero=True)
        bounded(self.input_context_tokens, MAX_TOKENS)
        bounded(self.max_output_tokens, 8192)
        bounded(self.input_micro_usd_per_million, MAX_AMOUNT)
        bounded(self.output_micro_usd_per_million, MAX_AMOUNT)
        output = bounded(args['max_output_tokens'], 8192)
        if (wall_time >= self.expires_unix or args['provider'] != 'openai'
                or args['model'] != self.model or output > self.max_output_tokens):
            raise Denied('No current exact model price policy')
        # Reserve the full configured model input context, not a guessed tokenizer
        # count. Cache discounts are ignored. Round the combined price upward.
        numerator = (self.input_context_tokens * self.input_micro_usd_per_million
                     + output * self.output_micro_usd_per_million)
        money = (numerator + 999999) // 1000000
        tokens = self.input_context_tokens + output
        bounded(money, MAX_AMOUNT)
        bounded(tokens, MAX_TOKENS)
        return dict(money=money, tokens=tokens)


def begin_priced(state, action_id, *, policy, now, boot_id, wall_time):
    """Trusted executor entry: price binding + reserve + original attempt commit."""
    if type(policy) is not PricePolicy:
        raise ValueError('Trusted immutable price policy required')
    with state.transaction():
        _, request = ModelStore(state).action(action_id, boot_id)
        args = json.loads(request.args_json)
        quote = policy.quote(args, wall_time=wall_time)
        approved = ModelBudget(state).begin(action_id, now=now, boot_id=boot_id, **quote)
        state.db.execute('INSERT INTO model_prices VALUES(?,?)',
                         (action_id, canonical(asdict(policy))))
        state.event(action_id, 'model-price-reservation', dict(model=policy.model,
            price_revision=policy.revision, expires_unix=policy.expires_unix,
            input_context_tokens=policy.input_context_tokens,
            input_micro_usd_per_million=policy.input_micro_usd_per_million,
            output_micro_usd_per_million=policy.output_micro_usd_per_million,
            money_micro_usd=quote['money'], tokens=quote['tokens']))
        return approved


def finish_priced(state, action_id, packet, *, boot_id):
    """Settle only against the durable original quote, atomically with custody."""
    from mano_protocol.provider import MAX_RESPONSE, decode

    with state.transaction():
        _, request = ModelStore(state).action(action_id, boot_id)
        row = state.db.execute('SELECT policy_json FROM model_prices WHERE action_id=?',
                               (action_id,)).fetchone()
        if row is None:
            raise Denied('Original model price reservation missing')
        policy = PricePolicy(**json.loads(row['policy_json']))
        policy.quote(json.loads(request.args_json), wall_time=0)  # Validate saved bounds.
        response = decode(packet, MAX_RESPONSE)
        usage = response.get('usage', {}) if isinstance(response, dict) else {}
        if not isinstance(usage, dict):
            raise Denied('Provider usage is not a bounded record')
        inputs, outputs = usage.get('input_tokens'), usage.get('output_tokens')
        if (type(inputs) is not int or type(outputs) is not int or inputs < 0 or outputs < 0
                or inputs > policy.input_context_tokens or outputs > policy.max_output_tokens):
            raise Denied('Provider usage exceeds original priced bounds')
        money = (inputs * policy.input_micro_usd_per_million
                 + outputs * policy.output_micro_usd_per_million + 999999) // 1000000
        result = ModelStore(state).finish(action_id, packet, boot_id=boot_id)
        ModelBudget(state).settle(action_id, boot_id=boot_id, money=money, tokens=inputs + outputs)
        return result
