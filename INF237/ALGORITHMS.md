# INF237 Algorithm Summary

---

## Table of Contents
1. [Sliding Window](#sliding-window)
2. [Dynamic Programming I](#dynamic-programming-i)
3. [Graph Algorithms — MST & Shortest Path](#graph-algorithms--mst--shortest-path)
4. [Segment Trees](#segment-trees)
5. [Computational Geometry](#computational-geometry)
6. [Exponential Time & Implicit Graphs](#exponential-time--implicit-graphs)
7. [Dynamic Programming II](#dynamic-programming-ii)
8. [Network Flow](#network-flow)
9. [BFS Variants (JavaScript)](#bfs-variants-javascript)
6. [Exponential Time & Implicit Graphs](#exponential-time--implicit-graphs)
7. [Dynamic Programming II](#dynamic-programming-ii)
8. [Network Flow](#network-flow)

---

## Sliding Window

**Files:** `SlidingSearchingSorting/deq.cpp`, `sound.cpp`

### Sliding Window Maximum/Minimum (Monotonic Deque)

**Problem:** Find the max (or min) in every window of size k over an array of n elements.

**Naive:** Scan k elements per window → O(nk)  
**Smart:** Monotonic deque → **O(n)**

**How it works:**
- The deque stores **indices** (not values). Invariant: values at stored indices are monotonically decreasing (for max).
- When adding element `i`:
  1. **Expire front:** remove indices outside the window (`front <= i - k`)
  2. **Maintain invariant:** pop from back any index whose value `<=` the new value
  3. Push `i` to back
  4. `arr[deque.front()]` = current window max

```
arr = [8, 9, 6, 1, 2, 5, 7], k = 3

i=0: deque=[0]        (val=8)
i=1: pop 0 (8≤9), deque=[1]    (val=9)
i=2: deque=[1,2]      (val=9,6)   window max = arr[1] = 9
i=3: expire 1 (out of window), pop 2 (6>1? no). deque=[2,3] → max = arr[2] = 6
```

**For min/max simultaneously** (sound.cpp): run two deques in parallel — one monotonically decreasing (max), one monotonically increasing (min).

---

## Dynamic Programming I

### 0/1 Knapsack
**File:** `DynamicProgramming/knapsack.cpp`

**Problem:** n items with values and weights. Maximise value without exceeding capacity. Each item taken at most once.

**State:** `dp[i][j]` = max value using first `i` items with capacity `j`

**Recurrence:**
```
dp[i][j] = max(
  dp[i-1][j],                          // skip item i
  val[i-1] + dp[i-1][j - wt[i-1]]     // take item i (only if wt[i-1] <= j)
)
```

**Traceback:** Walk backwards from `dp[n][cap]`. If `dp[i][j] != dp[i-1][j]` → item `i` was taken; subtract `wt[i-1]` from `j`.

**Time:** O(n × cap) | **Space:** O(n × cap)

---

### Grid Path Counting DP
**File:** `DynamicProgramming/watchyourstep2.cpp`

**Problem:** Count paths from top-left to bottom-right of a grid, moving only right or down, avoiding obstacle cells.

**State:** `dp[x][y]` = number of paths to reach cell (x, y)

**Recurrence:**
```
dp[0][0] = 1
dp[x][y] = 0                          if (x,y) is a mine
dp[x][y] = dp[x-1][y] + dp[x][y-1]   otherwise
```

**Time:** O(width × height)

---

## Graph Algorithms — MST & Shortest Path

### Prim's Minimum Spanning Tree
**Files:** `graphii/treehouses.cpp`, `treehouses2.cpp`

**Problem:** Connect n nodes on a 2D plane with minimum total edge cost. Some pairs are pre-connected for free (cost 0).

**Algorithm:** Prim's (simple O(n²) version)
- `dists[v]` = cheapest edge to add v to the MST (starts at ∞, except node 0 = 0)
- Repeat n times: pick the non-MST node with smallest `dists[]`, add to MST, relax neighbours

```
Start: dists=[0, ∞, ∞, ∞]
Step 1: pick node 0, add to MST. Relax: update dists[1,2,3] with edge weights from 0.
Step 2: pick cheapest remaining, add. Relax its neighbours.
...
```

**Zero-cost edges:** `zeroEdges[i][j] = true` → pre-built passage, costs 0 to include.

**Time:** O(n²) | **Note:** `treehouses.cpp` has a dangling pointer bug — `treehouses2.cpp` is the correct version.

---

### Modified Dijkstra — Latest Departure Time
**File:** `graphii/arrivingontime.cpp`

**Problem:** Bus network with periodic schedules. Must arrive at stop n-1 by time s. Find the LATEST departure from stop 0.

**Key idea:** Run Dijkstra **backwards** from the destination.
- `latest[v]` = latest time you can arrive at v and still make it to n-1 by time s
- For each edge `u → v` with schedule (t0, period p, duration d):
  - Find the latest arrival at v ≤ `latest[v]`:  
    `arrival = (t0+d) + floor((latest[v] - (t0+d)) / p) * p`
  - Departure from u = `arrival - d`

**Time:** O((V+E) log V)

---

### Modified Dijkstra — Maximum Probability Path
**Files:** `graphi/d.cpp`, `comp/getshorty.cpp`

**Problem:** Edge weights are probabilities (0–1). Find path from 0 to n-1 that maximises the **product** of edge weights.

**Changes from standard Dijkstra:**
| Standard | Max-Probability |
|----------|----------------|
| Minimise sum | Maximise product |
| `dist[0] = 0` | `dist[0] = 1.0` |
| `dist[v] = dist[u] + w` | `dist[v] = dist[u] * w` |
| Min-heap | Max-heap |

**Time:** O((V+E) log V)

---

### Brexit Cascade
**Files:** `comp/brexit.cpp`, `graphi/g.cpp`

**Problem:** Countries lose partners in a cascade. A country leaves if its remaining partners ≤ half its original count.

**Algorithm:** DFS via stack
1. Push the initial leaver onto a stack
2. Pop: for each of its partners, remove it from their list. If partner's count drops to ≤ half original → push partner
3. If the target country is ever pushed → "leave"

**Time:** O(p) where p = total partnerships (each edge removed at most once)

---

## Segment Trees

### Structure (Flat Array, Bottom-Up)

```
Array positions:   [0, 1, 2, 3]   (n=4 elements)
Tree indices:      internal [1..n-1], leaves [n..2n-1]

         [1] root
        /     \
     [2]       [3]
    /   \     /   \
  [4]  [5] [6]  [7]   ← leaves: arr[0..3]
```

- **Leaves:** `tree[i + n]` holds the value at position `i`
- **Internal nodes:** `tree[i] = f(tree[2i], tree[2i+1])`

### Point Update — O(log n)
```
pos += n          // go to leaf
tree[pos] = value
while pos > 1:
    pos /= 2      // go to parent
    tree[pos] = tree[2*pos] + tree[2*pos+1]
```

### Range Query [l, r] — O(log n) — Two-Pointer Technique
```
l += n; r += n
while l <= r:
    if l is right child (l%2==1): include tree[l], l++
    if r is left child  (r%2==0): include tree[r], r--
    l /= 2; r /= 2
```

**Files:**
- `SegmentTrees/moviecollection.cpp` — Range count of "movies above" using virtual positions
- `SegmentTrees/justforsidekicks.cpp` — Per-gem-type count arrays at each node (6-type gems)
- `graphi/c.cpp` — Generic templated segment tree class

---

## Computational Geometry

### Cross Product & Orientation
**File:** `Geometryi/jabuke.cpp`

```
cross(a, b) = a.x*b.y - a.y*b.x
orient(a, b, c) = cross(b-a, c-a)
  > 0 → c is LEFT of a→b  (counter-clockwise)
  < 0 → c is RIGHT         (clockwise)
  = 0 → collinear
```

**Triangle area:** `|orient(a, b, c)| / 2`

**Point in triangle:** A point P is inside CCW triangle (a,b,c) if it is to the left of every directed edge. Checked via `in_angle` using two orientation tests.

---

### DSU (Disjoint Set Union / Union-Find)
**File:** `Geometryi/undetected.cpp`

**Operations:**
- `find(x)` — returns root of x's component. Uses **path compression**: after finding root, all nodes on path point directly to root → nearly O(1) amortised
- `unionSet(x, y)` — merge by **rank**: attach smaller-depth tree under larger-depth tree → keeps tree height O(log n)

**Application:** Sensor coverage — sensors form a barrier from left wall to right wall if they are connected via overlapping circles. Add sensors one by one; stop when `find(LEFT) == find(RIGHT)`.

---

## Exponential Time & Implicit Graphs

### IDA* (Iterative Deepening A*)
**File:** `ExponentialTimeAndImplicitGraphs/knightsfen.cpp`

**Problem:** Knight's fen puzzle — reach a goal state in ≤ 10 knight moves.

**Algorithm:** IDA* = DFS + iterative depth limit + heuristic pruning
```
for maxMoves = 0, 1, ..., 10:
    run DFS with depth limit maxMoves
    prune if: current_depth + h(state) > maxMoves
```

**Heuristic:** `h(state) = cells_different_from_goal / 2` (admissible — never overestimates)

**Time:** O(8^k) worst case, much better with pruning

---

### 2-SAT (Two Satisfiability)
**File:** `ExponentialTimeAndImplicitGraphs/wedding.cpp`

**Problem:** Boolean variables with clauses of the form `(x OR y)`. Is there an assignment satisfying all clauses?

**Encoding:** `(x OR y)` ↔ `(¬x → y) AND (¬y → x)` — add both implications to the graph.

**Literal indexing:**
```
var(x)  = 2x     (positive literal: x is TRUE)
neg(x)  = 2x+1   (negative literal: x is FALSE)
neg(x)  = x ^ 1  (XOR trick to flip between them)
```

**Algorithm: Kosaraju's SCC**
1. DFS on original graph → record finish order
2. DFS on reversed graph in reverse finish order → assign SCC IDs
3. If `comp[x] == comp[¬x]` for any variable → UNSATISFIABLE
4. Assignment: `x = TRUE` if `comp[x] > comp[¬x]`

**Time:** O(V + E)

---

### Graph Coloring — Three Approaches

**Problem:** Find minimum colors χ(G) such that no two adjacent nodes share a color.

#### 1. Backtracking + MRV
**File:** `coloring.cpp`

Try k = 1, 2, 3, ... colors. For each k, backtrack:
- **MRV (Minimum Remaining Values):** always color the node with fewest available colors first
- **Forward checking:** after assigning a color, prune if any neighbour gets 0 options

#### 2. Bitmask DP over Subsets
**File:** `coloringbitmask.cpp`

Chromatic number = minimum number of independent sets covering all nodes.

```
is_independent[mask] = no two nodes in mask are adjacent

dp[mask] = min colors to color exactly the nodes in mask
dp[mask] = min over independent subsets S ⊆ mask:
             dp[mask ^ S] + 1
```

**Time:** O(3^n) | **Space:** O(2^n) | **Limit:** n ≤ ~25

#### 3. DSatur + Branch and Bound
**File:** `coloring3.cpp`

- **DSatur** (Degree of Saturation): node selection heuristic — always color the node with the **most distinct colors already used by its neighbours**
- Greedy pass first for an upper bound, then backtrack to improve
- Prune branches that can't beat the current best

---

## Dynamic Programming II

### TSP — Held-Karp Bitmask DP
**Files:** `DynamicProgrammingII/errands.cpp`, `comp/main.cpp`

**Problem:** Visit all k errand locations starting from "work", ending at "home". Find minimum total distance.

**State:** `dp[mask][i]` = min distance starting from work, visiting all locations in `mask`, last at location `i`

```
Base:  dp[1<<i][i] = dist(work, errand_i)

Trans: dp[mask | (1<<j)][j] = min(dp[mask][i] + dist(errand_i, errand_j))
       for all i in mask, j not in mask

Answer: min over i of dp[FULL_MASK][i] + dist(errand_i, home)
```

**Path reconstruction:** `parent[mask][i]` = previous location; trace back from `(FULL_MASK, bestLast)`.

**Time:** O(2^k × k²) | **Space:** O(2^k × k) | **Limit:** k ≤ ~20

---

### Greedy Scheduling — Minimise Weighted Completion Time
**Files:** `comp/errands.cpp`, `graphi/d2.cpp`

**Problem:** n tasks with base cost `p`, rate `r`, duration `d`. Minimise `Σ(p_i + r_i × start_time_i)`.

**Exchange argument:** A before B is better iff `r_B × d_A < r_A × d_B`

**Greedy:** Sort by `d × (total_rate - r)` ascending — tasks that impose least delay on others go first.

**Time:** O(n log n)

---

### Tree DP — Company Picnic
**Files:** `DynamicProgrammingII/companypicnic.cpp`, `ExponentialTimeAndImplicitGraphs/wedding.cpp` (for tree structure)

**Problem:** In a company hierarchy tree, build a team where each member is either alone or paired with a direct report. Maximise team size (then speed).

**States per node v:**
- `alone[v]` = best (size, speed) in v's subtree where v is available to pair upward
- `onTeam[v]` = best assuming v pairs with one of its direct reports

**Recurrence:**
```
onTeam[v] = Σ alone[child]   (no pairing for v yet)

For each child c, consider pairing v with c:
  size  = onTeam[v].size  - alone[c].size  + onTeam[c].size  + 1
  speed = onTeam[v].speed - alone[c].speed + onTeam[c].speed + min(v.speed, c.speed)
alone[v] = best candidate
```

**Traversal:** Iterative post-order via stack (leaves before parents).

---

## Network Flow

### Edmonds-Karp Maximum Flow
**Files:** `networkFlow/maze.cpp`, `networkFlow/mazecomments.cpp`

**Problem:** Find maximum flow from source s to sink t through a capacity-constrained network.

**Key concepts:**

| Concept | Explanation |
|---------|-------------|
| **Residual graph** | `cap[u][v]` starts at edge capacity; decreases as flow is pushed. Backward edges `cap[v][u]` start at 0 and grow (allow "undoing" flow) |
| **Augmenting path** | A path s→t where all edges have `cap > 0`. Push flow = min cap on path (bottleneck) |
| **Edmonds-Karp** | Ford-Fulkerson where augmenting path is found via **BFS** (shortest path). Guarantees O(VE²) regardless of capacities |
| **Max-flow min-cut** | When no augmenting path exists, flow = capacity of the minimum cut |

**Algorithm:**
```
while BFS finds a path from s to t:
    bottleneck = min cap along the path
    for each edge (u,v) on the path:
        cap[u][v] -= bottleneck   // forward: used capacity
        cap[v][u] += bottleneck   // backward: can undo later
    total_flow += bottleneck
```

**Time:** O(VE²)

**Application (maze.cpp):** Rooms connected if `gcd(room[i], room[j]) > 1`; edge capacity = gcd. Find max flow between smallest and largest rooms.

---

### Gale-Ryser Theorem — Binary Matrix Existence
**File:** `networkFlow/tomography.cpp`

**Problem:** Given row sums and column sums, does a 0/1 matrix exist with those sums?

**Theorem:** Such a matrix exists if and only if, after sorting column sums descending:
```
For all k: Σ(top k column sums) ≤ Σ_j min(row_j, k)
```

**Greedy check:** For each row sum `r`:
1. Sort column sums descending
2. Distribute `r` ones to the top `r` columns (decrement those sums by 1)
3. If any column goes negative → impossible

**Necessary conditions (quick pre-check):**
- Total row sums = Total column sums
- Max row sum ≤ Number of non-zero column sums
- Max col sum ≤ Number of non-zero row sums

---

---

## BFS Variants (JavaScript)

### Bidirectional BFS — Happy Hookup
**File:** `graphi/happyhookup.js`

**Problem:** Given a directed graph and two start nodes A and B, find a node reachable from **both**.

**Algorithm:** Run two BFS searches simultaneously, one from each start. Alternate expanding one node per side. Stop as soon as a node in one frontier is already in the other's reachable set.

```
reachable_from_a = {start_a}      reachable_from_b = {start_b}
queue_a = [start_a]                queue_b = [start_b]

loop:
  expand next node from queue_a:
    for each neighbour val:
      if val in reachable_from_b → FOUND, output val
      else enqueue val, add to reachable_from_a

  expand next node from queue_b:
    for each neighbour val:
      if val in reachable_from_a → FOUND, output val
      else enqueue val, add to reachable_from_b
```

**Why bidirectional?** Stops as soon as the two frontiers meet — much earlier than running two separate full BFS passes.

**Implementation detail:** Uses a head pointer (`head_a++`) instead of `queue.shift()` to dequeue in O(1) — `shift()` on a JS array is O(n).

**Time:** O(V + E) worst case, faster in practice | **Space:** O(V)

---

### Carl's Maze-Solving Algorithm — Left-Hand Rule
**File:** `graphi/carsmazesolvingalgorithm.js`

**Problem:** Given a 2D grid, simulate Carl's specific movement rule and determine if he reaches the exit.

**Carl's Rule (Left-Hand Rule / Wall-Following):**
At each step, try in order:
1. **Turn left** and step forward — if that cell is open (`'0'`), take it
2. **Go straight** — if that cell is open, take it
3. **Turn right in place** — rotate without moving, then retry next step

```
Direction indices: 0=right, 1=up, 2=left, 3=down
Turn left  = (dir + 1) % 4
Turn right = (dir - 1 + 4) % 4   (+4 prevents negative modulo in JS)
```

**Loop detection:** State = `(x, y, direction)`. If Carl revisits the same state → infinite loop → output `"0"`.

**Why this can fail:** Left-hand rule only guarantees exit in *simply-connected* mazes (no isolated wall islands). In mazes with loops, Carl may circle a wall island forever — the visited set detects this.

**Diagram:**
```
Carl facing right (→), wall on left:
  Try left (↑): blocked
  Try straight (→): open → move right

Carl in a corner, wall ahead and left:
  Try left: blocked
  Try straight: blocked
  Turn right: now facing down, no movement
  Next step: try left (→): might be open
```

**Time:** O(rows × cols × 4) — at most 4 direction states per cell before loop detected

---

## Quick Reference

| Algorithm | Time | Key Idea |
|-----------|------|----------|
| Sliding Window Max | O(n) | Monotonic deque of indices |
| 0/1 Knapsack | O(n·cap) | 2D DP table, take or skip |
| Grid Path Count | O(w·h) | DP accumulate from left and above |
| Prim's MST | O(n²) | Greedy: always add cheapest non-MST node |
| Dijkstra (max prob) | O((V+E)logV) | Max-heap, multiply weights |
| Dijkstra (latest dep) | O((V+E)logV) | Backwards from destination |
| Brexit Cascade | O(E) | Stack-based DFS cascade |
| Bidirectional BFS | O(V+E) | Two frontiers, stop when they meet |
| Left-Hand Rule (maze) | O(V·4) | Turn left → straight → right; loop detect via state |
| Segment Tree query | O(log n) | Two-pointer from leaves |
| DSU find | O(α(n)) | Path compression + union by rank |
| IDA* | O(b^d) | DFS + depth limit + admissible heuristic |
| 2-SAT | O(V+E) | Implication graph + Kosaraju SCC |
| Graph Coloring (backtrack) | O(k^n) | MRV + forward checking |
| Graph Coloring (bitmask) | O(3^n) | DP over independent set subsets |
| Graph Coloring (DSatur) | O(k^n) | Saturation heuristic + branch+bound |
| TSP Held-Karp | O(2^k · k²) | Bitmask DP over visited subsets |
| Greedy Scheduling | O(n log n) | Sort by delay-cost, exchange argument |
| Tree DP | O(n·k²) | Post-order, merge child DPs |
| Edmonds-Karp | O(VE²) | BFS augmenting paths, residual graph |
| Gale-Ryser | O(n log n) | Greedy column distribution |
