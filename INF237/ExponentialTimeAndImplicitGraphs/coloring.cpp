// =============================================================
// GRAPH COLORING — Backtracking with MRV Heuristic
// =============================================================
//
// PROBLEM: Find the minimum number of colors (chromatic number χ(G))
//          needed to color a graph so no two adjacent nodes share a color.
//
// ALGORITHM: Backtracking + Minimum Remaining Values (MRV) Heuristic
//
//   Outer loop: try k = 1, 2, 3, ... colors until a valid k-coloring is found.
//   Inner: backtracking DFS:
//     - At each step, choose the UNCOLORED node with the FEWEST available colors
//       (MRV / "fail-first" heuristic — catches dead ends early).
//     - If any uncolored node has 0 available colors → prune immediately.
//     - Try each valid color for the chosen node → recurse → backtrack if needed.
//
// MRV (Minimum Remaining Values):
//   Choosing the most constrained variable first reduces the search tree.
//   If a node already has 0 colors available with only k total, that branch
//   is doomed — better to discover this high up in the tree.
//
// FORWARD CHECKING (light version):
//   After assigning color c to node v, check if any UNCOLORED neighbour
//   of v now has 0 available colors. If so, prune immediately.
//
// DIAGRAM (4-cycle, k=2):
//   0 - 1
//   |   |
//   3 - 2
//   Try color 1 for node 0. Then node 1 (neighbor of 0) must use color 2.
//   Then node 2 (neighbor of 1) must use color 1. Then node 3 (neighbor of 0
//   and 2) → both colors used → BACKTRACK. Try k=3.
//
// TIME: Exponential in the worst case, but pruning makes it practical for small graphs.
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

bool solve(int a, int k, vector<Node> &nodes);
int countAvailable(int v, int k, vector<Node> &nodes);

int n;
vector<int> node_colors; // node_colors[i] = color of node i (-1 if uncolored)

int main() {
  cin.tie(nullptr);
  ios::sync_with_stdio(false);
  cin.exceptions(ios::failbit);
  cin >> n;
  cin.ignore();

  vector<Node> nodes(n);
  for (int i = 0; i < n; i++) nodes[i].id = i;

  // Read adjacency list: each line contains neighbor indices for node i
  for (int i = 0; i < n; i++) {
    string line;
    getline(cin, line);
    stringstream ss(line);
    int neighbor_index;
    while (ss >> neighbor_index) {
      nodes[i].neighbors.push_back(neighbor_index);
    }
  }

  // Try increasing numbers of colors until a valid coloring is found
  for (int k = 1; k <= n; k++) {
    node_colors.assign(n, -1); // reset all colors to "uncolored"
    if (solve(0, k, nodes)) {
      cout << k << endl;
      break;
    }
  }
  return 0;
}

// Backtracking solver for k-coloring.
// a = number of nodes colored so far.
bool solve(int a, int k, vector<Node> &nodes) {
  if (a == n) return true; // all nodes colored → success!

  // MRV: pick the uncolored node with the FEWEST available colors
  int v = -1;
  int bestC = k + 1;
  for (int i = 0; i < nodes.size(); i++) {
    if (node_colors[i] != -1) continue; // already colored, skip

    int c = countAvailable(i, k, nodes);
    if (c == 0) return false; // no colors left for this node → prune immediately
    if (c < bestC) {
      v = i;
      bestC = c;
    }
  }

  // Collect colors already used by neighbors of v
  vector<bool> used(k + 1, false);
  for (int n : nodes[v].neighbors) {
    if (node_colors[n] != -1) {
      used[node_colors[n]] = true; // this color is taken by a neighbor
    }
  }

  // Try each valid color for v
  for (int c = 1; c <= k; c++) {
    if (used[c]) continue; // color c is used by a neighbor → skip

    node_colors[v] = c; // tentatively assign color c

    // FORWARD CHECKING: after assigning c to v, check if any uncolored
    // neighbor now has 0 available colors → if so, prune this branch
    bool ok = true;
    for (int nb : nodes[v].neighbors) {
      if (node_colors[nb] == -1 && countAvailable(nb, k, nodes) == 0) {
        ok = false;
        break;
      }
    }

    if (ok) {
      if (solve(a + 1, k, nodes)) return true; // recurse
    }

    node_colors[v] = -1; // backtrack: undo assignment
  }
  return false; // no valid color worked → backtrack further
}

// Count how many colors (1..k) are still available for node v.
// A color is unavailable if any COLORED neighbor uses it.
int countAvailable(int v, int k, vector<Node> &nodes) {
  vector<bool> used(k + 1, false);
  for (int n : nodes[v].neighbors) {
    if (node_colors[n] != -1)
      used[node_colors[n]] = true;
  }
  int count = 0;
  for (int c = 1; c <= k; c++)
    if (!used[c]) count++;
  return count;
}
