// =============================================================
// GRAPH COLORING — DSatur + Backtracking (Branch and Bound)
// =============================================================
//
// PROBLEM: Find the chromatic number χ(G) of a graph.
//
// ALGORITHM: DSatur heuristic + backtracking with branch-and-bound pruning.
//
// PHASE 1 — Greedy DSatur (upper bound):
//   For each node in order (1..n), assign the lowest available color.
//   This greedy pass gives an UPPER BOUND on the chromatic number (best = k).
//
// PHASE 2 — DSatur Backtracking:
//   Try to improve on the greedy solution by finding a coloring with fewer colors.
//   Node selection: at each step pick the uncolored node with the highest
//   SATURATION (number of DISTINCT colors already used by its neighbours).
//   Tie-break: prefer the node with the highest degree.
//
//   DSatur is much better than simple MRV because saturation directly measures
//   how constrained a node is by already-placed colors (not just by count).
//
//   Branch and bound: only try colors 0..min(k-1, best-1).
//   best = current best (upper bound from greedy or from previously found colorings).
//   If k (colors used so far + 1 for this node) >= best → prune.
//
// KEY FUNCTIONS:
//   saturation(v): count of distinct colors among colored neighbours of v.
//   validColor(v,c): check that no neighbour of v is colored c.
//   solve(a, k): try to color node a using at most k colors so far.
//
// TIME: Exponential worst case; DSatur ordering makes it fast for most real graphs.
// =============================================================

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

struct Node {
  int id;
  vector<int> neighbors;
};

void solve(int a, int k, vector<int> &node_colors, vector<Node> &nodes);

int n;
int best; // current best (minimum) number of colors found

int main() {
  cin >> n;
  vector<Node> nodes(n);
  for (int i = 0; i < n; i++) nodes[i].id = i;

  string line;
  getline(cin, line);
  for (int i = 0; i < n; i++) {
    getline(cin, line);
    istringstream ss(line);
    int nb;
    while (ss >> nb)
      nodes[i].neighbors.push_back(nb);
  }

  // ── PHASE 1: Greedy coloring for upper bound ──────────────────────────
  // Assign each node the smallest color not used by its already-colored neighbors.
  vector<int> node_colors(n, -1);
  best = 0;
  for (int i = 0; i < n; i++) {
    vector<bool> used(n, false);
    for (int nb : nodes[i].neighbors)
      if (node_colors[nb] != -1)
        used[node_colors[nb]] = true;

    for (int c = 0; c < n; c++)
      if (!used[c]) {
        node_colors[i] = c;
        break;
      }
    best = max(best, node_colors[i] + 1); // track highest color used
  }
  // Now 'best' is the greedy upper bound.

  // ── PHASE 2: Backtracking to find minimum ─────────────────────────────
  node_colors.assign(n, -1);
  solve(0, 0, node_colors, nodes); // 0 nodes colored, 0 colors used so far

  cout << best << endl;
  return 0;
}

// Saturation of node v = number of DISTINCT colors among its colored neighbours.
int saturation(int v, vector<int> &node_colors, vector<Node> &nodes) {
  vector<bool> seen(best, false);
  int sat = 0;
  for (int nb : nodes[v].neighbors)
    if (node_colors[nb] != -1 && !seen[node_colors[nb]]) {
      seen[node_colors[nb]] = true;
      sat++;
    }
  return sat;
}

// Returns true if color c is valid for node v (no neighbour uses it)
bool validColor(int v, int c, vector<int> &node_colors, vector<Node> &nodes) {
  for (int nb : nodes[v].neighbors)
    if (node_colors[nb] == c) return false;
  return true;
}

// Backtracking with DSatur node selection.
// a = nodes colored so far, k = colors used so far in this partial solution.
void solve(int a, int k, vector<int> &node_colors, vector<Node> &nodes) {
  if (a == n) {
    // All nodes colored — update best if this uses fewer colors
    best = min(best, k);
    return;
  }

  // DSatur: pick the uncolored node with the highest saturation.
  // Tie-break: higher degree.
  int v = -1;
  int bestSat = -1;
  int bestDeg = -1;

  for (int i = 0; i < n; i++) {
    if (node_colors[i] != -1) continue; // already colored

    int sat = saturation(i, node_colors, nodes);
    int deg = (int)nodes[i].neighbors.size();
    if (sat > bestSat || (sat == bestSat && deg > bestDeg)) {
      v = i;
      bestSat = sat;
      bestDeg = deg;
    }
  }

  // Try colors 0..maxC (pruning: don't try a color >= best since we can't improve)
  int maxC = min(k, best - 1); // k = max color used + 1 would introduce a new color
  for (int c = 0; c <= maxC; c++) {
    if (!validColor(v, c, node_colors, nodes)) continue;

    node_colors[v] = c;
    // max(k, c+1): if c is a new color, k increases; otherwise stays same
    solve(a + 1, max(k, c + 1), node_colors, nodes);
    node_colors[v] = -1; // backtrack
  }
}
