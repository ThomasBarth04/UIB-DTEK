
import numpy as np
import unicodedata
import matplotlib.pyplot as plt

# @title Genererer reproduserbar tilfeldighet ut i fra navnet ditt.
#

navn = "Thomas Mogstad Barth"

bytenavn = unicodedata.normalize("NFKD", navn).encode("ascii", "ignore")
seed = int.from_bytes(bytenavn)
rng = np.random.default_rng(seed)
n = x1 = 4 + (int(100 * rng.random()) % 4)
x0 = (-(int(100 * rng.random()) % 4) - 1)/10
x1 = (1 + int(100 * rng.random()) % 4)/10
a = -(int(100 * rng.random()) % 3) + 2
b = (int(100 * rng.random()) % 4) + 4


def w(x):
    res = 0
    for i in range(3):
        res = res + np.cos((n**i)*np.pi*x)/(2**i)
    return res


# 3
def wderivert(x):
    """
    w(x) = cos(n^0 * π * x) / 2^0 + cos(n^1 * π * x) / 2^1 + cos(n^2 * π * x) / 2^2
    w(x) = cos(π * x) + cos(n * π * x) / 2 + cos(n^2 * π * x) / 4

    Den deriverte blir:
    w'(x) = -π * sin(π * x) - (n * π / 2) * sin(n * π * x) - (n^2 * π / 4) * sin(n^2 * π * x)
    """

    res = 0
    for i in range(3):
        res = res - (n**i) * np.pi * np.sin((n**i) * np.pi * x) / (2**i)
    return res


fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=True)

x_fa = np.linspace(-0.1, 0.2, 20)
w_numerisk_fa = np.gradient(w(x_fa), x_fa[1] - x_fa[0])
w_eksakt_fa = wderivert(x_fa)

axes[0].plot(x_fa, w_numerisk_fa, 'ro-', linewidth=2,
             markersize=6, label='Numerisk derivert', alpha=0.7)
axes[0].plot(x_fa, w_eksakt_fa, 'b^-', linewidth=2,
             markersize=6, label='Eksakt derivert', alpha=0.7)

axes[0].set_title("Få punkter (20)", fontsize=14)
axes[0].set_xlabel('x', fontsize=12)
axes[0].set_ylabel("w'(x)", fontsize=12)
axes[0].grid(True, alpha=0.3)
axes[0].axhline(y=0, color='k', linewidth=0.5)
axes[0].axvline(x=0, color='k', linewidth=0.5)

x_mange = np.linspace(-0.1, 0.2, 1000)
w_numerisk_mange = np.gradient(w(x_mange), x_mange[1] - x_mange[0])
w_eksakt_mange = wderivert(x_mange)

axes[1].plot(x_mange, w_numerisk_mange, 'r-', linewidth=2,
             label='Numerisk derivert', alpha=0.8)
axes[1].plot(x_mange, w_eksakt_mange, 'b--', linewidth=2,
             label='Eksakt derivert', alpha=0.8)

axes[1].set_title("Mange punkter (1000)", fontsize=14)
axes[1].set_xlabel('x', fontsize=12)
axes[1].grid(True, alpha=0.3)
axes[1].axhline(y=0, color='k', linewidth=0.5)
axes[1].axvline(x=0, color='k', linewidth=0.5)

plt.suptitle("Sammenligning av numerisk og eksakt derivert", fontsize=16)
plt.tight_layout(rect=[0, 0, 1, 0.95])
plt.show()
