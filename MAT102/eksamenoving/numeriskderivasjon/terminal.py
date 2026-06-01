import numpy as np


def f(x):
    return (x**3) - 4*(x**2) + 1


def fd_numeric(x, dx):
    return (f(x+dx) - f(x))/dx


def fd_analytical(x):
    return 3*x**2 - 8 * x


print("fd_numeric: ", fd_numeric(5, 0.001))
print("fd_analytical: ", fd_analytical(5))
