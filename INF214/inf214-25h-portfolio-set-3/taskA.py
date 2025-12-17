from heapq import heappush, heappop
from collections import deque
from dataclasses import dataclass, field
from functools import partial

# ---------------- Core Event Loop ----------------


@dataclass(order=True)
class Macrotask:
    when: int
    fn: callable = field(compare=False)
    duration: int = field(default=0, compare=False)


@dataclass
class Microtask:
    fn: callable
    duration: int = 0


class JSEventLoopSimulator:
    def __init__(self):
        """
        Initialize the JavaScript event loop simulator:
            - self.time_ms: current simulated time in milliseconds.
            - self._macrotasks: a priority queue (min-heap) of macrotasks,
                each with an execution time (like setTimeout / setInterval).
            - self._microtasks: a queue (FIFO) of microtasks (like Promise callbacks).
        """
        self.time_ms = 0
        self._macrotasks = []
        self._microtasks = deque()
        self.logs = []

    def _log(self, msg):
        """
        Log a message along with the current simulated time.
        Appends the log entry to self.logs and prints it to the console.
        """
        self.logs.append((self.time_ms, msg))
        print(f"[{self.time_ms:>5} ms] {msg}")

    def set_timeout(self, delay, duration, fn):
        """
        Simulate JavaScript's setTimeout.

        Schedules a macrotask that will execute 'fn' after 'delay' milliseconds.
        The 'duration' parameter simulates how long the function takes to execute.
        """
        when = self.time_ms + delay
        heappush(self._macrotasks, Macrotask(
            when, partial(fn, self._log), duration))

    def set_interval(self, interval, duration, fn, count=None):
        """
        Simulate JavaScript's setInterval.

        Repeatedly schedules a macrotask every 'interval' milliseconds that executes 'fn'.
        If 'count' is None, the interval repeats forever; otherwise, it repeats 'count' times.

        Implementation detail:
        - Each interval execution re-schedules itself by recursively calling set_interval().
        """
        """Schedule a repeating macrotask. Count=None means infinite."""

        def make_wrapper(remaining):
            def _run(log):
                # Execute the user function
                fn(log)
                # Re-schedule according to remaining runs
                if remaining is None:
                    # infinite
                    self.set_interval(interval, duration, fn, None)
                else:
                    # finite
                    if remaining - 1 > 0:
                        self.set_interval(interval, duration,
                                          fn, remaining - 1)
            return _run

        first_when = self.time_ms + interval
        heappush(self._macrotasks, Macrotask(
            first_when, partial(make_wrapper(count), self._log), duration))

    def schedule_event_callback(self, when, fn):
        """
        Schedule an event callback to fire at an exact simulated time.

        The function 'fn' will be called when simulation time reaches 'when'.
        """
        heappush(self._macrotasks, Macrotask(when, partial(fn, self._log), 0))

    def queue_microtask(self, duration, fn):
        """.
        Adds 'fn' to the microtask queue. Microtasks are executed:
        - Immediately after the current macrotask finishes,
        - Before any new macrotask starts.

        The 'duration' simulates the execution time of the microtask.
        """
        self._microtasks.append(Microtask(partial(fn, self._log), duration))

    def code_block(self, duration, fn):
        """
        Execute a synchronous code block immediately.
        Simulates running a block of JavaScript code.

        - Runs the provided function 'fn' immediately.
        - Advances the simulated time by 'duration' milliseconds to reflect blocking execution.
        """
        fn(self._log)
        self.time_ms += duration

    def run(self):
        """
        Run the event loop simulation until all tasks are complete.

        The loop processes tasks in the following order:
        1. Drain all pending microtasks.
        2. Execute the next scheduled macrotask from the priority queue.
        3. Each task may schedule new microtasks or macrotasks.

        The simulated clock advances as tasks consume 'duration' time.
        """

        while self._microtasks or self._macrotasks:
            self._drain_microtasks()
            if not self._macrotasks:
                break
            task = heappop(self._macrotasks)
            # Advance to its scheduled time (never backwards)
            if task.when > self.time_ms:
                self.time_ms = task.when
            # Execute and then account for duration
            task.fn()
            self.time_ms += task.duration

    def _drain_microtasks(self):
        """
        Execute all queued microtasks.

        Microtasks are processed continuously until the queue is empty.
        - The simulated time advances by each microtask's 'duration'.

        This mimics JavaScript's behavior where microtasks run immediately
        after a macrotask and before the next macrotask.
        """

        while self._microtasks:
            mt = self._microtasks.popleft()
            mt.fn()
            self.time_ms += mt.duration


# ---------------- DSL Layer ----------------

class Statements:
    def __init__(self, loop):
        self.loop = loop

    def _log_action(self, msg):
        def runner(log):
            log(msg)
        return runner

    def _set_timeout_action(self, delay, msg, duration):
        def runner(log):
            self.loop.set_timeout(delay, duration, self._log_action(msg))
        return runner

    def _set_interval_action(self, interval, msg, duration, count=None):
        def runner(log):
            self.loop.set_interval(
                interval, duration, self._log_action(msg), count)
        return runner

    def _promise_resolve_action(self, promise_name):
        def runner(log):
            log(f"Promise {promise_name} resolved")
        return runner

    def _promise_then_action(self, promise_name, duration):
        def runner(log):
            self.loop.queue_microtask(
                duration, self._log_action(promise_name + ".then"))
        return runner

    def _code_block(self, msg, duration):
        def runner(log):
            self.loop.code_block(duration, self._log_action(msg))
        return runner

    def handler(self, statements_list, msg, log):
        """
        statements_list is a list of tuples like:
        [
            ("CODE_BLOCK", "clickHandling", 1),
            ("SET_TIMEOUT", 0, "delayedFunction", 3),
            ("SET_INTERVAL", 10, "intervalFunction", 3, 3),
            ("PROMISE_RESOLVE", "p1"),
            ("PROMISE_THEN", "p1", 2)
        ]
        """

        log(msg)
        for stmt in statements_list:
            match stmt[0]:
                case "SET_TIMEOUT":
                    self._set_timeout_action(*stmt[1:])(log)

                case "SET_INTERVAL":
                    self._set_interval_action(*stmt[1:])(log)

                case "PROMISE_RESOLVE":
                    self._promise_resolve_action(*stmt[1:])(log)

                case "PROMISE_THEN":
                    self._promise_then_action(*stmt[1:])(log)

                case "CODE_BLOCK":
                    self._code_block(*stmt[1:])(log)

                case _:
                    raise ValueError(f"Unknown statement kind: {stmt[0]}")

    # --------------- Top-level Statements ---------------
    def add_SET_TIMEOUT(self, delay, msg, duration):
        self.loop.set_timeout(delay, duration, self._log_action(msg))

    def add_SET_INTERVAL(self, interval, msg, duration, count=None):
        self.loop.set_interval(
            interval, duration, self._log_action(msg), count)

    def add_PROMISE_RESOLVE(self, promise_name):
        self._promise_resolve_action(promise_name)(self.loop._log)

    def add_PROMISE_THEN(self, promise_name, duration):
        self.loop.queue_microtask(
            duration, self._log_action(promise_name + ".then"))

    def execute_CODE_BLOCK(self, msg, duration):
        self.loop.code_block(duration, self._log_action(msg))

    # --------------- Declarative functions with callbacks ---------------
    def add_SET_TIMEOUT_CALLBACK(self, delay, msg, statements_list):
        self.loop.schedule_event_callback(
            when=delay,
            fn=partial(self.handler, statements_list, msg)
        )

    def add_BUTTON_CLICK_HANDLER(self, click_time, msg, statements_list):
        self.loop.schedule_event_callback(
            when=click_time,
            fn=partial(self.handler, statements_list, msg)
        )


# ---------------- DEMO ----------------

if __name__ == "__main__":
    loop = JSEventLoopSimulator()
    s = Statements(loop)

    s.add_SET_TIMEOUT(10, "timeoutHandler", duration=6)
    s.add_BUTTON_CLICK_HANDLER(
        click_time=5,
        msg="clickHandler",
        statements_list=[
            ("CODE_BLOCK", "clickCode", 1),
            ("SET_TIMEOUT", 0, "delayedFunction", 7),
            ("PROMISE_RESOLVE", "p1"),
            ("PROMISE_THEN", "p1", 4),
        ]
    )
    s.add_SET_INTERVAL(10, "intervalHandler", duration=8, count=4)
    s.execute_CODE_BLOCK("mainline", 15)

    loop.run()
