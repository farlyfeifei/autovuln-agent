"""Webdemo internals: SSE broadcast fan-out and stop-reason correctness."""
import queue
import threading
import unittest

import webdemo.app as app


class EmitBroadcastTest(unittest.TestCase):
    def setUp(self):
        with app._CLIENTS_LOCK:
            app._CLIENTS.clear()
        app._STATE.update(running=False, results=[], steps_emitted=0,
                          total_challenges=0)
        app._STATE["stop"].clear()

    def tearDown(self):
        with app._CLIENTS_LOCK:
            app._CLIENTS.clear()
        app._STATE["stop"].clear()

    def _register(self) -> "queue.Queue":
        q = queue.Queue(maxsize=app._MAX_CLIENT_QUEUE)
        with app._CLIENTS_LOCK:
            app._CLIENTS.add(q)
        return q

    def test_emit_reaches_every_client(self):
        q1 = self._register()
        q2 = self._register()
        app._emit({"type": "step", "index": 1})
        self.assertEqual(q1.get_nowait()["type"], "step")
        self.assertEqual(q2.get_nowait()["type"], "step")
        self.assertTrue(q1.empty())
        self.assertTrue(q2.empty())

    def test_slow_client_drops_oldest_not_stall(self):
        q = queue.Queue(maxsize=2)
        q.put("oldest")
        q.put("older")
        with app._CLIENTS_LOCK:
            app._CLIENTS.add(q)
        app._emit({"type": "step"})
        got = []
        while not q.empty():
            got.append(q.get_nowait())
        self.assertEqual(got, ["older", {"type": "step"}])

    def test_done_reason_stopped_when_stop_set_at_start(self):
        q = self._register()
        app._STATE["stop"].set()
        t = threading.Thread(target=app._run_benchmark, daemon=True)
        t.start()
        t.join(timeout=30)
        reasons = [e.get("reason") for e in self._drain(q)
                   if e.get("type") == "done"]
        self.assertIn("stopped", reasons)
        self.assertNotIn("completed", reasons)

    def test_done_reason_completed_for_normal_run(self):
        q = self._register()
        t = threading.Thread(target=app._run_benchmark, daemon=True)
        t.start()
        t.join(timeout=30)
        reasons = [e.get("reason") for e in self._drain(q)
                   if e.get("type") == "done"]
        self.assertIn("completed", reasons)
        self.assertNotIn("stopped", reasons)

    def _drain(self, q):
        events = []
        while not q.empty():
            events.append(q.get_nowait())
        return events


if __name__ == "__main__":
    unittest.main()
