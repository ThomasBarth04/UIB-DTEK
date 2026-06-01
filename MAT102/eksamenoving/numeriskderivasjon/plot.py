import numpy as np
import matplotlib.pyplot as plt


def f(x):
    return x**3 - 4*x**2 + 1


def fd_numeric(x, dx):
    return (f(x + dx) - f(x)) / dx


def fd_analytical(x):
    return 3*x**2 - 8*x


x = np.arange(-2, 3, 0.001)  # fixed: small step for a smooth curve

plt.plot(x, f(x),                "r", label="f(x)")
plt.plot(x, fd_analytical(x),    "b", label="f'(x) analytical")
plt.plot(x, fd_numeric(x, 0.00001), "g", label="f'(x) numerical")
plt.legend()
plt.show()
