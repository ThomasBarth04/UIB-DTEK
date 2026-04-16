// =============================================================
// GRAPH COLORING — Backtracking with MRV + Incremental Forward Checking
// =============================================================
//
// PROBLEM: Find the chromatic number χ(G) — the minimum number of colors
//          needed so no two adjacent nodes share the same color.
//
// ─────────────────────────────────────────────────────────────
// HOW IT FITS IN THE COLORING HIERARCHY:
//
//   coloring.cpp       — basic backtracking + MRV, recomputes available
//                        colors from scratch at each forward-check step (slow)
//   coloringsat.cpp    — same idea, but tracks available_count[] INCREMENTALLY
//                        (this file — the efficient version)
//   coloring3.cpp      — DSatur heuristic + branch-and-bound
//   coloringbitmask.cpp— bitmask DP over independent sets (exact, O(3^n))
//
// ─────────────────────────────────────────────────────────────
// KEY DATA STRUCTURE — available_count[v]:
//
//   available_count[v] = how many of the k colors are still valid for node v.
//   "Valid" = not used by any already-colored neighbour of v.
//
//   Instead of recomputing this from scratch each time (O(k) scan of neighbours),
//   we MAINTAIN it:
//     - When we assign color c to node v:
//         for each UNCOLORED neighbour nb where c was still valid:
//             available_count[nb]--        ← c is now off the table for nb
//             remember nb in nReduced[]    ← so we can undo this later
//     - When we BACKTRACK (un-assign c from v):
//         for each nb in nReduced[]:
//             available_count[nb]++        ← c is back on the table for nb
//
//   This makes each assignment/backtrack step O(degree(v)) instead of O(k·degree(v)).
//
// ─────────────────────────────────────────────────────────────
// MRV (MINIMUM REMAINING VALUES) HEURISTIC:
//
//   At each step, pick the UNCOLORED node with the FEWEST available colors.
//   If that count is 0 → prune immediately (this branch is already dead).
//
//   Intuition: picking the most-constrained node first causes failures to
//   surface high in the search tree, pruning huge subtrees early.
//
//   Tie-break by DEGREE: among nodes with equal available_count, pick the
//   one with more neighbours. This tends to constrain more nodes sooner.
//
// ─────────────────────────────────────────────────────────────
// FORWARD CHECKING:
//
//   Before recursing with color c assigned to v, CHECK whether any uncolored
//   neighbour now has 0 available colors. If so, that branch is already dead —
//   prune WITHOUT recursing.
//
//   This is exactly what the available_count decrement step achieves:
//   if available_count[nb] hits 0, set possible=false and skip the recursion.
//
// ─────────────────────────────────────────────────────────────
// WORKED EXAMPLE (triangle graph: 0-1, 1-2, 0-2, try k=3):
//
//   Initial: available_count = [3, 3, 3]  (all nodes can use any of 3 colors)
//
//   MRV picks node 0 (all tied; pick first). Try color 1:
//     Neighbours of 0: {1, 2}. Color 1 was valid for both.
//     available_count[1]-- → 2,  available_count[2]-- → 2
//     nReduced = [1, 2],  possible = true
//     Recurse: a=1
//
//     MRV picks node 1 (available=2, same as 2; pick first). Try color 1:
//       validColor(1, 1)? Node 0 has color 1 → NO. Skip.
//     Try color 2:
//       validColor(1, 2)? Yes.
//       Neighbours of 1: {0, 2}. Node 0 already colored, skip.
//       Color 2 valid for node 2? Yes. available_count[2]-- → 1. nReduced=[2]
//       possible = true. Assign color[1] = 2. Recurse: a=2
//
//       MRV picks node 2 (only one left, available=1). Try color 1:
//         validColor(2, 1)? Node 0 has color 1 → NO. Skip.
//       Try color 2:
//         validColor(2, 2)? Node 1 has color 2 → NO. Skip.
//       Try color 3:
//         validColor(2, 3)? Yes. No uncolored neighbours. Recurse: a=3
//         a == n → return true! ✓ Chromatic number = 3.
//
// ─────────────────────────────────────────────────────────────
// WHY START k AT max_degree?
//
//   A node with d coloured neighbours needs at least 1 color not used by them.
//   If degree(v) = d, you need at least d colors just for v's neighbourhood.
//   So χ(G) >= max_degree in general (actually χ(G) >= max_degree is not always
//   tight, but it's a valid lower bound and avoids wasted tries with too few colors).
//
//   Exception: complete graphs need n colors. Bipartite graphs need only 2.
//   The loop from startK to n catches all cases.
//
// ─────────────────────────────────────────────────────────────
// TIME:  Exponential worst-case — O(k^n) without pruning.
//        With MRV + incremental forward checking, typically far better.
// SPACE: O(n·k) for the coloring arrays + O(n) for nReduced stack.
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

bool solve(int a, int k, vector<int> &node_colors, vector<Node> &nodes,
           vector<int> &available_count);
int n;

int main() {
  cin >> n;
  vector<Node> nodes(n);
  for (int i = 0; i < n; i++) nodes[i].id = i;

  // Read adjacency list: each line i contains the space-separated neighbour IDs of node i
  string line;
  getline(cin, line); // consume the newline left after reading n
  for (int i = 0; i < n; i++) {
    getline(cin, line);
    istringstream ss(line);
    int nb;
    while (ss >> nb)
      nodes[i].neighbors.push_back(nb);
  }

  // LOWER BOUND: need at least max_degree colors.
  // A node with d neighbours: all d neighbour colors must be distinct from v's color.
  // Therefore we need at least (max_degree) colors in the worst case.
  // Starting here avoids trying k=1, k=2, ... up to max_degree — all guaranteed to fail.
  int startK = 1;
  for (int i = 0; i < n; i++)
    startK = max(startK, (int)nodes[i].neighbors.size());

  // Try k = startK, startK+1, ... until a valid k-coloring is found
  for (int k = startK; k <= n; k++) {
    vector<int> color(n, -1);              // -1 = uncolored
    vector<int> available_count(n, k);    // all k colors available for every node initially
    if (solve(0, k, color, nodes, available_count)) {
      cout << k << endl;
      break;
    }
    // If solve returns false: no valid k-coloring exists → try k+1
  }
  return 0;
}

// validColor: returns true if color c can be assigned to node v right now.
// A color is INVALID if any already-colored neighbour of v already uses it.
// O(degree(v))
bool validColor(int v, int c, vector<int> &node_colors, vector<Node> &nodes) {
  for (int nb : nodes[v].neighbors)
    if (node_colors[nb] == c) return false; // conflict!
  return true;
}

// solve: backtracking search for a valid k-coloring.
//
// Parameters:
//   a              — number of nodes colored so far (used only to detect completion)
//   k              — number of colors we're allowed to use
//   node_colors    — current (partial) coloring; -1 = uncolored
//   nodes          — the graph
//   available_count— available_count[v] = # colors still valid for uncolored node v
//
// Returns true if a complete valid k-coloring is found from this state.
bool solve(int a, int k, vector<int> &node_colors, vector<Node> &nodes,
           vector<int> &available_count) {

  // BASE CASE: all n nodes have been assigned a color → valid coloring found!
  if (a == (int)nodes.size()) return true;

  // ── MRV NODE SELECTION ──────────────────────────────────────────────────
  // Find the uncolored node with the FEWEST available colors.
  // If that count is 0 → the current partial assignment is already invalid → prune.
  // Tie-break: among equal available_count, prefer the node with more neighbours
  //            (higher degree = will constrain more nodes when colored).
  int v = -1;
  int bestC = k + 1; // bestC = smallest available_count seen so far (starts impossibly high)

  for (int i = 0; i < n; i++) {
    if (node_colors[i] != -1) continue; // skip already-colored nodes

    if (available_count[i] == 0)
      return false; // this node has NO valid color left → dead end, prune immediately

    bool betterCount = available_count[i] < bestC;
    bool tieBreakDeg = (available_count[i] == bestC) && v != -1
                       && nodes[i].neighbors.size() > nodes[v].neighbors.size();

    if (betterCount || tieBreakDeg) {
      v = i;
      bestC = available_count[i];
    }
  }
  // After the loop, v = the chosen node to color next.

  // ── nReduced: tracking which neighbours got decremented ─────────────────
  // When we try color c for node v, some uncolored neighbours will lose c
  // as a valid option (we decrement available_count[nb]).
  // We store those neighbours in nReduced[] so we can UNDO the decrements
  // when backtracking to try the next color.
  //
  // NOTE: int nReduced[n] is a C99-style VLA (variable-length array).
  // This is non-standard in C++ but supported by GCC as an extension.
  // A vector<int> would be the portable alternative.
  int nReduced[n];
  int nReducedSize = 0; // number of entries used in nReduced

  // ── TRY EACH COLOR for node v ────────────────────────────────────────────
  for (int c = 1; c <= k; c++) {

    // CONSISTENCY CHECK: skip c if a colored neighbour already uses it.
    // (We haven't touched available_count yet, so we're just filtering.)
    if (!validColor(v, c, node_colors, nodes)) continue;

    // Reset the nReduced list for this color attempt
    nReducedSize = 0;
    bool possible = true; // will be set to false if forward checking kills a neighbour

    // ── FORWARD CHECKING ──────────────────────────────────────────────────
    // Assigning color c to v means c is no longer available for any uncolored
    // neighbour nb that could previously use c.
    // Decrement available_count[nb] for each such nb and record nb in nReduced[].
    // If any nb reaches 0 → this branch is dead → set possible=false and stop.
    for (int nb : nodes[v].neighbors) {
      if (node_colors[nb] != -1) continue; // nb already colored → skip (no impact)

      // Was color c still valid for nb BEFORE assigning v?
      // validColor checks nb's already-colored neighbours — NOT v yet (v is still -1).
      if (validColor(nb, c, node_colors, nodes)) {
        // Yes — c was valid for nb. Now that v will use c, c becomes invalid for nb.
        available_count[nb]--;
        nReduced[nReducedSize++] = nb; // remember to restore this later

        if (available_count[nb] == 0) {
          // nb has run out of options entirely → this color choice for v is a dead end
          possible = false;
          break; // no need to check further neighbours
        }
      }
      // If c was ALREADY invalid for nb (due to some other neighbour), do nothing —
      // our assignment of c to v doesn't change nb's count (c wasn't in nb's pool).
    }

    // ── RECURSE ───────────────────────────────────────────────────────────
    if (possible) {
      node_colors[v] = c; // tentatively assign color c to v

      if (solve(a + 1, k, node_colors, nodes, available_count))
        return true; // solution found deeper in the tree — propagate success up

      node_colors[v] = -1; // BACKTRACK: undo the color assignment
    }

    // ── RESTORE available_count ───────────────────────────────────────────
    // Whether we recursed or were pruned (possible=false), we must undo the
    // decrements we made to available_count[] before trying the next color.
    // Walk nReduced[] and increment each entry back.
    for (int i = 0; i < nReducedSize; i++)
      available_count[nReduced[i]]++;
    // After this, available_count[] is back to what it was before we tried color c.
  }

  // All k colors exhausted for node v with no solution found → return false
  // (caller will either try the next color for ITS node, or propagate failure)
  return false;
}
