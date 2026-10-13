"""Private LangGraph SQLite checkpoints, always reconciled with the broker journal."""

import hashlib
import os
import sqlite3
import stat
from pathlib import Path

from mano_protocol.actions import canonical, identifier, text

from .runtime import AgentRuntime


class Session:
    def __init__(self, directory, model, broker):
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
        from langgraph.checkpoint.sqlite import SqliteSaver

        if os.geteuid() == 0:
            raise ValueError('Agent checkpoints must never be opened as root')
        folder = Path(directory).absolute()
        if folder.resolve() != folder:
            raise ValueError('Checkpoint directory must have no symlink components')
        folder.mkdir(mode=0o700, exist_ok=True)
        info = folder.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('Expected private agent-owned checkpoint directory')
        file = folder / 'graph.sqlite'
        fd = os.open(file, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > 4 * 1024**2):
                raise ValueError('Expected private single-link checkpoint file')
            conn = sqlite3.connect(file, check_same_thread=False)
            current = file.lstat()
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                conn.close()
                raise ValueError('Checkpoint file identity changed')
        finally:
            os.close(fd)
        try:
            conn.execute('PRAGMA trusted_schema=OFF')
            conn.execute('PRAGMA synchronous=FULL')
            if (conn.execute('PRAGMA page_size').fetchone()[0] != 4096
                    or conn.execute('PRAGMA max_page_count=1024').fetchone()[0] != 1024):
                raise ValueError('Checkpoint database exceeds supported page budget')
            conn.execute('PRAGMA journal_size_limit=4194304')
            conn.execute('PRAGMA wal_autocheckpoint=64')
            conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
            serde = JsonPlusSerializer(pickle_fallback=False, allowed_json_modules=[],
                                       allowed_msgpack_modules=[])
            self.runtime = AgentRuntime(model, broker, checkpointer=SqliteSaver(conn, serde=serde))
        except BaseException:
            conn.close()
            raise
        self.connection = conn
        self.closed = False

    def step(self, context):
        if self.closed or set(context) != {'task_id', 'resource_id', 'operation_key', 'prompt'}:
            raise ValueError('Expected fixed task context')
        identifier(context['task_id'])
        identifier(context['resource_id'])
        text(context['operation_key'], 128)
        text(context['prompt'], 8192)
        thread = hashlib.sha256(canonical(dict(task_id=context['task_id'],
            operation_key=context['operation_key'])).encode()).hexdigest()
        saved = self.runtime.graph.get_state({'configurable': {'thread_id': thread}}).values
        if saved and any(saved.get(key) != value for key, value in context.items()):
            raise ValueError('Checkpoint cannot change task scope or original prompt')
        # Fresh journal status is queried by AgentRuntime even for completed snapshots.
        return self.runtime.step(saved or context, thread_id=thread)

    def close(self):
        if not self.closed:
            self.connection.close()
            self.closed = True
