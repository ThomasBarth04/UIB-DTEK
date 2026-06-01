import numpy as np
import matplotlib.pyplot as plt


def newton(f, n):
    a = -9999
    while (f(a) * f(a+1) > 0):
        a += 1
    a, b = a-1, a

    for i in range(n):
        a = a - f(x) / np.gradient(f, x)

    return a


def f(x):
    return x*np.e**(-x**2)


x = np.arange(-3, 3, 0.001)

plt.plot(x, f(x))
plt.show()
