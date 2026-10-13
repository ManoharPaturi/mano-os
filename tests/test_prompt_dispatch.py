import queue
import threading
import unittest

from mano_prompt.dispatch import SubmissionWorker


class PromptDispatchTests(unittest.TestCase):
    def test_single_inflight_and_completion_only_on_ui_thread(self):
        started, release = threading.Event(), threading.Event()
        posted = queue.Queue()
        owner = threading.get_ident()
        calls, completions = [], []

        def submit(prompt):
            calls.append((prompt, threading.get_ident()))
            started.set()
            self.assertTrue(release.wait(2))
            return {'id': 'a' * 32}

        def finished(result, error):
            completions.append((result, error, threading.get_ident()))

        worker = SubmissionWorker(submit, lambda *args: posted.put(args))
        try:
            self.assertTrue(worker.start('goal', finished))
            self.assertTrue(started.wait(2))
            self.assertFalse(worker.start('duplicate', finished))
            self.assertTrue(worker.busy)
            self.assertEqual(completions, [])
        finally:
            release.set()
        callback, *args = posted.get(timeout=2)
        self.assertTrue(worker.busy)
        self.assertFalse(callback(*args))
        self.assertFalse(worker.busy)
        self.assertEqual(completions, [({'id': 'a' * 32}, False, owner)])
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0][1], owner)

    def test_uncertain_result_is_not_retried_or_exposed(self):
        posted = queue.Queue()
        calls, results = [], []

        def submit(prompt):
            calls.append(prompt)
            raise OSError('private service detail')

        worker = SubmissionWorker(submit, lambda *args: posted.put(args))
        self.assertTrue(worker.start('goal', lambda *args: results.append(args)))
        callback, *args = posted.get(timeout=2)
        callback(*args)
        self.assertEqual(calls, ['goal'])
        self.assertEqual(results, [(None, True)])
        self.assertFalse(worker.busy)
