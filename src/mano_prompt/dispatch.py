"""One in-flight submission; completion is posted to the human UI thread."""

import threading


class SubmissionWorker:
    def __init__(self, submit, post):
        self.submit, self.post = submit, post
        self.busy = False

    def start(self, prompt, finished):
        # Called only from the UI thread. The worker never changes UI state.
        if self.busy:
            return False
        self.busy = True

        def complete(result, error):
            self.busy = False
            finished(result, error)
            return False

        def run():
            try:
                result = self.submit(prompt)
            except Exception:
                self.post(complete, None, True)
            else:
                self.post(complete, result, False)

        try:
            threading.Thread(target=run, name='mano-prompt-submit', daemon=True).start()
        except RuntimeError:
            self.busy = False
            raise
        return True
