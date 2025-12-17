# INF214 H25 Portfolio Set 3 - JavaScript event-loop

## Delivering this Portfolio Set 

- The Portfolio Set will be delivered and automatically graded through CodeGrade.
- The submission link is available at [MittUiB](https://mitt.uib.no/courses/53850/assignments/110593).
- :rotating_light: Deadline: **23:59, 7th of November 2025**. :rotating_light:

## Installing `Python` and running demo and tests
- Please follow the instructions given at https://python.org/doc/
  * The tests on CodeGrade are set to run with Python version `3.12`
- To run the tests, you will need to install `pytest`
  * Please follow the instructions given at https://docs.pytest.org/en/stable/getting-started.html
  * NB! You might need to setup a virtual environment to be able to install packages with pip
    * Please follow the instruction given at https://docs.python.org/3/library/venv.html
  
- The demo can be run by simply running taskA.py and the tests can be run by navigating to the `tests` folder and running the command `pytest`.

## Task A. Scheduled when?

Your task is to implement a **simplified** version of the Event Loop for a heavily simplified version of JavaScript.

Here is an example of how one could write a "program" in this "language":

```js
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
```
This code should be executed in the following order and timestamps.
```
[    0 ms] mainline
[   15 ms] clickHandler
[   15 ms] clickCode
[   16 ms] Promise p1 resolved
[   16 ms] p1.then
[   20 ms] timeoutHandler
[   26 ms] intervalHandler
[   34 ms] delayedFunction
[   41 ms] intervalHandler
[   51 ms] intervalHandler
[   61 ms] intervalHandler
```

In the file [taskA.py](taskA.py), you will find the description of each of the "features" of the "language".
Your task is to implement all of the functions that contain a TODO.