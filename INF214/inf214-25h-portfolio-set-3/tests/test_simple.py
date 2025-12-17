import sys
import pytest
sys.path.append('../../inf214-25h-portfolio-set-3')
from taskA import JSEventLoopSimulator, Statements

def compare_output(expected, capsys):
    captured = tuple(x.strip() for x in capsys.readouterr().out.splitlines())
    expected = tuple(x.strip() for x in expected.splitlines())

    assert captured == expected


def test_simple(capsys):

    loop = JSEventLoopSimulator()
    s = Statements(loop)

    s.add_SET_INTERVAL(10, "intervalHandler", duration=10, count=2)
    s.add_SET_TIMEOUT(10, "timeoutHandler", duration=10)
    s.execute_CODE_BLOCK("mainline", 10)
    loop.run()

    expected = """[    0 ms] mainline
[   10 ms] intervalHandler
[   20 ms] timeoutHandler
[   30 ms] intervalHandler"""

    compare_output(expected, capsys)


def test_demo(capsys):
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

    expected = """[    0 ms] mainline
[   15 ms] clickHandler
[   15 ms] clickCode
[   16 ms] Promise p1 resolved
[   16 ms] p1.then
[   20 ms] timeoutHandler
[   26 ms] intervalHandler
[   34 ms] delayedFunction
[   41 ms] intervalHandler
[   51 ms] intervalHandler
[   61 ms] intervalHandler"""

    compare_output(expected, capsys)


def test_negative_delay(capsys):

    loop = JSEventLoopSimulator()
    s = Statements(loop)

    s.add_SET_INTERVAL(-10, "intervalHandler", duration=10, count=2)
    s.add_SET_TIMEOUT(-10, "timeoutHandler", duration=10)
    s.execute_CODE_BLOCK("mainline", 15)
    loop.run()

    expected = """[    0 ms] mainline
[   15 ms] intervalHandler
[   25 ms] timeoutHandler
[   35 ms] intervalHandler"""

    compare_output(expected, capsys)


def test_setTimeout_callback(capsys):
    loop = JSEventLoopSimulator()
    s = Statements(loop)

    s.add_SET_TIMEOUT(10, "timeoutHandler", duration=6)
    s.add_SET_TIMEOUT_CALLBACK(
        delay=6,
        msg="clickHandler",
        statements_list=[
            ("CODE_BLOCK", "clickCode", 2),
            ("SET_TIMEOUT", 0, "delayedFunction", 7),
            ("PROMISE_RESOLVE", "p1"),
            ("PROMISE_THEN", "p1", 5),
        ]
    )
    s.add_SET_INTERVAL(10, "intervalHandler", duration=8, count=4)
    s.execute_CODE_BLOCK("mainline", 12)

    loop.run()

    expected = """[    0 ms] mainline
[   12 ms] clickHandler
[   12 ms] clickCode
[   14 ms] Promise p1 resolved
[   14 ms] p1.then
[   19 ms] timeoutHandler
[   25 ms] intervalHandler
[   33 ms] delayedFunction
[   40 ms] intervalHandler
[   50 ms] intervalHandler
[   60 ms] intervalHandler"""

    compare_output(expected, capsys)


def test_promise(capsys):
    loop = JSEventLoopSimulator()
    s = Statements(loop)

    s.add_SET_TIMEOUT(10, "timeoutHandler", duration=6)
    s.add_PROMISE_RESOLVE(("p1"))
    s.add_PROMISE_THEN("p1", duration=7)
    s.add_SET_INTERVAL(10, "intervalHandler", duration=8, count=4)
    s.execute_CODE_BLOCK("mainline", 12)

    loop.run()

    expected = """[    0 ms] Promise p1 resolved
[    0 ms] mainline
[   12 ms] p1.then
[   19 ms] timeoutHandler
[   25 ms] intervalHandler
[   35 ms] intervalHandler
[   45 ms] intervalHandler
[   55 ms] intervalHandler"""

    compare_output(expected, capsys)


def test_promise_two(capsys):
    loop = JSEventLoopSimulator()
    s = Statements(loop)

    s.add_SET_TIMEOUT(10, "timeoutHandler", duration=6)
    s.add_PROMISE_RESOLVE(("p1"))
    s.add_PROMISE_THEN("p1", duration=7)
    s.add_SET_INTERVAL(10, "intervalHandler", duration=8, count=4)
    s.execute_CODE_BLOCK("mainline", 12)
    s.add_PROMISE_RESOLVE(("p2"))
    s.add_PROMISE_THEN("p2", duration=7)

    loop.run()

    expected = """[    0 ms] Promise p1 resolved
[    0 ms] mainline
[   12 ms] Promise p2 resolved
[   12 ms] p1.then
[   19 ms] p2.then
[   26 ms] timeoutHandler
[   32 ms] intervalHandler
[   42 ms] intervalHandler
[   52 ms] intervalHandler
[   62 ms] intervalHandler"""

    compare_output(expected, capsys)