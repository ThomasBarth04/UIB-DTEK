import sys
import math

# -----------------------------
# Distance function (Euclidean)
# --{
#
# }---------------------------


def dist(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


# -----------------------------
# Read input
# -----------------------------
input = sys.stdin.read
data = input().strip().splitlines()

# Number of locations
n = int(data[0])

# Map: name -> (x, y)
mp = {}

for i in range(1, n + 1):
    name, x, y = data[i].split()
    mp[name] = (float(x), float(y))

# Remaining lines = queries (each day)
queries = data[n + 1:]


# -----------------------------
# Process each query
# -----------------------------
for line in queries:
    if not line.strip():
        continue

    errands = line.split()
    k = len(errands)

    work = mp["work"]
    home = mp["home"]

    # Coordinates of errands
    pts = [mp[name] for name in errands]

    # -----------------------------
    # Precompute distances
    # -----------------------------
    d = [[0.0] * k for _ in range(k)]
    d_work = [0.0] * k
    d_home = [0.0] * k

    for i in range(k):
        d_work[i] = dist(work, pts[i])
        d_home[i] = dist(pts[i], home)
        for j in range(k):
            d[i][j] = dist(pts[i], pts[j])

    # -----------------------------
    # Bitmask DP
    # dp[mask][i] = min cost to:
    #   start at work,
    #   visit mask,
    #   end at i
    # -----------------------------
    INF = float('inf')
    FULL = 1 << k

    dp = [[INF] * k for _ in range(FULL)]
    parent = [[-1] * k for _ in range(FULL)]

    # -----------------------------
    # Initialization
    # -----------------------------
    for i in range(k):
        dp[1 << i][i] = d_work[i]

    # -----------------------------
    # Transitions
    # -----------------------------
    for mask in range(FULL):
        for i in range(k):
            if not (mask & (1 << i)):
                continue

            if dp[mask][i] == INF:
                continue

            # Try to go to next errand j
            for j in range(k):
                if mask & (1 << j):
                    continue  # already visited

                new_mask = mask | (1 << j)
                val = dp[mask][i] + d[i][j]

                if val < dp[new_mask][j]:
                    dp[new_mask][j] = val
                    parent[new_mask][j] = i

    # -----------------------------
    # Final step: go to home
    # -----------------------------
    full = FULL - 1
    best = INF
    last = -1

    for i in range(k):
        val = dp[full][i] + d_home[i]
        if val < best:
            best = val
            last = i

    # -----------------------------
    # Reconstruct path
    # -----------------------------
    order = []
    mask = full
    cur = last

    while cur != -1:
        order.append(cur)
        prev = parent[mask][cur]
        mask ^= (1 << cur)
        cur = prev

    order.reverse()

    # -----------------------------
    # Output result
    # -----------------------------
    print(" ".join(errands[i] for i in order))
