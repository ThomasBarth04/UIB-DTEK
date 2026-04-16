# Her importeres Point og Daily funksjonalitetene fra meteostat modulen.
# Hvis meteostat ikke allerede er installert blir den installert.

import meteostat

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import scipy.stats
from datetime import datetime, timedelta
# Sett tidsperioden vi vil hente data fra
# Data for fremtiden kan ikke lastes inn, så når vi ber om å laste inn data får vi data helt opp til i dag.

start = datetime(1930, 1, 1)  # Sett inn rett dato her
end = datetime(1959, 12, 31)  # Sett inn rett dato her

# Målestasjon Florida Bergen
bergen = meteostat.daily('01317', start, end)
bergen = bergen.fetch()
# Målestasjon Blindern Oslo
oslo = meteostat.daily('01492', start, end)
oslo = oslo.fetch()

df = pd.DataFrame(index=bergen.index)
# Temperaturforskjellen vi tester for
forskjell = 1.5

# Vi bruker gjennomsnitt av daglig min og maks temperatur i stedet for daglig gjennomsnitt
bergen['bergen'] = 0.5*(bergen['tmin'] + bergen['tmax'])
oslo['oslo'] = 0.5*(oslo['tmin'] + oslo['tmax'])

df['differanse'] = bergen['bergen'] - oslo['oslo'] - forskjell

# gjennomsnitt og standardavvik
Edifferanse = np.mean(df['differanse'])
sigmadifferanse = np.std(df['differanse'])

t_verdi = Edifferanse/(sigmadifferanse / np.sqrt(len(df)))
antall_frihetsgrader = len(df) - 1

# @title plot

# Define the function
x = np.linspace(-4, 4, 1000)
# t-fordeling med 10 frihetsgrader
yy = scipy.stats.t.pdf(x, antall_frihetsgrader)
t_crit = t_verdi


def t_av_mu(m):
    return (forskjell + Edifferanse - m)/(sigmadifferanse / np.sqrt(len(df)))


def mu_av_t(t):
    return forskjell + Edifferanse - t*(sigmadifferanse / np.sqrt(len(df)))


ax = plt.gca()


plt.plot(x, yy, color='black')
plt.fill_between(x, yy, where=(x > t_crit), color='red',
                 alpha=0.5, label=r'P(H0)=P(μ1≤μ2)')
plt.fill_between(x, yy, where=(x < t_crit), color='blue',
                 alpha=0.5, label=r'P(H1)=P(μ1>μ2)')
# Remove default spines
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.spines["left"].set_visible(False)
ax.spines["bottom"].set_visible(False)

# Set limits
ax.set_xlim(-5, 5)
ax.set_ylim(-.2, .5)  # Ensure axes are visible

# Draw the primary x-axis (for x) with an arrow
ax.plot([-4, 4], [0, 0], color="black", lw=1.5)
ax.annotate("", xy=(4.1, 0), xytext=(4., 0),
            arrowprops=dict(arrowstyle="->", lw=1.5), annotation_clip=False)
ax.text(4.4, 0, r"t", verticalalignment="center")

# Draw the secondary x-axis (for -x) with an arrow
ax.plot([-4.1, 4], [-.1, -.1], color="black", lw=1.5)
ax.annotate("", xy=(4.1, -.1), xytext=(4., -.1),
            arrowprops=dict(arrowstyle="->", lw=1.5), annotation_clip=False)
ax.text(4.4, -.1, r"$\mu$", verticalalignment="center")

# Draw the y-axis with an arrow
ax.plot([0, 0], [0, .45], color="black", lw=1.5)
ax.annotate("", xy=(0, .46), xytext=(0, .45),
            arrowprops=dict(arrowstyle="->", lw=1.5), annotation_clip=False)
# ax.text(-0.3, .45, r"$y$", verticalalignment="center")

# Set x-ticks for t-axis
ticks = np.arange(-3, 4, 1)  # Tick positions

# Draw ticks for t-axis
for t in ticks:
    ax.plot([t, t], [-.01, .01], color="black", lw=1)  # Small tick marks
    ax.text(t, -.05, f"{t}", fontsize=10, ha="center")  # Labels below ticks

# Set ticks for $\mu$-axis
mu_min = mu_av_t(-3)
mu_maks = mu_av_t(3)
mu_verdier = np.linspace(mu_min, mu_maks, endpoint=True, num=8)
muticks = [t_av_mu(mu) for mu in mu_verdier]
# muticks = [mu_av_t(t) for t in ticks]
# Draw ticks for secondary x-axis (-x)
for t, mu in zip(muticks, mu_verdier):
    ax.plot([t, t], [-.11, -.09], color="black", lw=1)  # Small tick marks
    ax.text(t, -.15, f"{int(-100*mu)/100:.2f}",
            fontsize=10, ha="center")  # Labels below ticks

# Remove y-ticks
ax.set_yticks([])
ax.set_xticks([])
plt.legend()
plt.show()
