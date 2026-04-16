import matplotlib.pyplot as plt
import numpy as np

# says give me range from -100 to 100 and it should be 199 numbers in the range
x = np.linspace(-100, 100, 200)
# says give me a range from -100 to 100 where step = 1
# x = np.arange(-100, 100, 1)


def f(x):
    return x**2


f = np.vectorize(f)
y = f(x)


plt.plot(x, y)
plt.show()
