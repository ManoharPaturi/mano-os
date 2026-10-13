"""Model callback around the public Responses contract and an authorized relay."""

from mano_protocol.provider import configuration as configuration
from mano_protocol.provider import request_body as request_body
from mano_protocol.provider import response_plan as response_plan


class ResponsesPlanner:
    """Injected authorized relay; this adapter cannot select endpoints or credentials."""

    def __init__(self, relay, *, model, max_output_tokens):
        configuration(model, max_output_tokens)
        self.relay, self.model, self.max_output_tokens = relay, model, max_output_tokens

    def __call__(self, prompt):
        body = request_body(prompt, model=self.model, max_output_tokens=self.max_output_tokens)
        packet = self.relay(body)  # Exactly one call; failures are never retried here.
        return response_plan(packet, model=self.model, max_output_tokens=self.max_output_tokens)
