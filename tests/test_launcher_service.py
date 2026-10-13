import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from mano_broker.launch_controller import serve_control, serve_prepare
from mano_broker.launcher_service import iteration
from mano_broker.state import Denied


class LauncherServiceTests(unittest.TestCase):
    def test_abandoned_denial_reply_does_not_crash_launcher(self):
        for serve, receiver in (
            (serve_prepare, "mano_broker.launch_controller.receive_admission"),
            (serve_control, "mano_broker.launch_controller.receive"),
        ):
            connection = Mock()
            connection.sendall.side_effect = BrokenPipeError()
            with patch(receiver, side_effect=Denied("bad packet")):
                serve(Mock(), connection)
            connection.sendall.assert_called_once()

    def test_control_priority_budget_and_cleanup_sweep(self):
        selector = Mock()
        controller = Mock()
        keys = []
        for name in ("prepare", "control"):
            listener = Mock()
            connection = MagicMock()
            connection.__enter__.return_value = connection
            listener.accept.return_value = (connection, None)
            keys.append((SimpleNamespace(data=name, fileobj=listener), 1))
        selector.select.return_value = keys
        budgets = {name: Mock() for name in ("prepare", "control")}
        order = []
        with patch("mano_broker.launcher_service.serve_prepare",
                   side_effect=lambda *_: order.append("prepare")), \
             patch("mano_broker.launcher_service.serve_control",
                   side_effect=lambda *_: order.append("control")):
            iteration(selector, budgets, controller)
            self.assertEqual(order, ["control", "prepare"])
            budgets["prepare"].admit.return_value = False
            order.clear()
            iteration(selector, budgets, controller)
            self.assertEqual(order, ["control"])
        self.assertEqual(controller.sweep.call_count, 2)
