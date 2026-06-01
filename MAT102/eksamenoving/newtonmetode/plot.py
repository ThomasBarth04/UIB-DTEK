import numpy as np
import matplotlib.pyplot as plt

x = np.arange(-5, 5, 0.01)


def f(x):
    return (x**3) - 4*(x**2) + 1


fv = np.vectorize(f)
y = fv(x)


def f_d(x):
    return 3*x**2 - 8 * x


def find_start(f):
    first = -9999
    first_val = f(first)

    while first_val * f(first+1) > 0:
        first += 1
        first_val = f(first)

    return (first, first+1)


def newtons_method(f, n):
    a, b = find_start(f)
    for i in range(n):
        a = a - f(a)/f_d(a)

    return a


print(newtons_method(f, 10), f(newtons_method(f, 10)))
plt.plot(x, y)
plt.plot(newtons_method(f, 10), f(newtons_method(f, 10)), "ro")

plt.show()
print(newtons_method(f, 10))
