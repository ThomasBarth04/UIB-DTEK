import numpy as np


def f(x):
    return np.e**x - 4*x


def g(x):
    return np.e**x + np.cos(x)


def h(x):
    return x + np.log(x)


print(f(1))
