// =============================================================
// GRAPH COLORING via BITMASK DP — Chromatic Number
// =============================================================
//
// PROBLEM: Find the minimum number of colors to color a graph (chromatic number).
//
// ALGORITHM: Dynamic Programming over subsets (bitmask DP)
//
// KEY IDEA:
//   The chromatic number = minimum number of INDEPENDENT SETS that cover all nodes.
//   (Each color class must be an independent set — no two adjacent nodes share a color.)
//
// STEP 1 — Precompute which subsets are independent sets:
//   A subset S is an independent set if NO two nodes in S are adjacent.
//   is_independent[mask] = true if mask represents an independent set.
//   Check: for each node v in mask, (neighbors[v] & mask) == 0
//          i.e., no neighbor of v is also in mask.
//
// STEP 2 — DP over subsets:
//   dp[mask] = minimum number of colors needed to color exactly the nodes in mask.
//   Recurrence:
//     dp[mask] = min over all independent subsets S ⊆ mask:
//                  dp[mask ^ S] + 1
//   (remove an independent set S from mask, color those nodes with one color,
//    recurse on the remaining nodes)
//
// ENUMERATE SUBSETS: for each mask, iterate over all non-empty subsets:
//   for (int sub = mask; sub > 0; sub = (sub - 1) & mask)
//   This enumerates all submasks of mask in O(3^n) total across all masks.
//
// BITMASK REPRESENTATION:
//   Node v is in mask if bit v is set: (mask >> v) & 1
//   neighbors stored as bitmask: nodes[v].neighbors = bitmask of adjacent nodes
//
// TIME: O(3^n) — sum of subsets enumeration
// SPACE: O(2^n)
// Practical limit: n ≤ ~25
//
// DIAGRAM (triangle: 0-1, 1-2, 0-2):
//   neighbors[0] = 0b110 = 6   (adjacent to 1 and 2)
//   neighbors[1] = 0b101 = 5   (adjacent to 0 and 2)
//   neighbors[2] = 0b011 = 3   (adjacent to 0 and 1)
//   Independent sets: {0},{1},{2} only (no edges allowed in a set)
//   dp[111] = dp[110]+1 = dp[100]+1+1 = ... = 3
// =============================================================

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

struct Node {
  int id;
  int neighbors; // bitmask: bit v set if node v is adjacent
};

int main() {
  int n;
  cin >> n;

  vector<Node> nodes(n);
  for (int i = 0; i < n; i++) nodes[i].id = i;

  string line;
  getline(cin, line); // consume newline after n

  // Read adjacency as bitmasks
  for (int i = 0; i < n; i++) {
    getline(cin, line);
    istringstream ss(line);
    int nb;
    while (ss >> nb) {
      nodes[i].neighbors |= (1 << nb); // set bit nb in node i's neighbor mask
      nodes[nb].neighbors |= (1 << i); // undirected → also set bit i in node nb
    }
  }

  int total = 1 << n; // 2^n total subsets

  // STEP 1: Precompute independent set membership for all subsets
  vector<bool> is_independent(total, true);
  for (int mask = 1; mask < total; mask++) {
    for (int v = 0; v < n; v++) {
      if (!((mask >> v) & 1)) continue; // v not in mask → skip

      // If any neighbor of v is also in mask → not independent
      if (nodes[v].neighbors & mask) {
        is_independent[mask] = false;
        break;
      }
    }
  }

  // STEP 2: DP over subsets
  vector<int> dp(total, n + 1); // initialise to impossibly large value
  dp[0] = 0; // empty set needs 0 colors

  for (int mask = 1; mask < total; mask++) {
    // Try all non-empty independent subsets of mask as the next color class
    for (int sub = mask; sub > 0; sub = (sub - 1) & mask) {
      if (!is_independent[sub]) continue; // sub must be an independent set

      // Color all nodes in sub with one color; solve the rest
      if (dp[mask ^ sub] + 1 < dp[mask])
        dp[mask] = dp[mask ^ sub] + 1;
    }
  }

  // dp[(1<<n)-1] = chromatic number of the full graph
  cout << dp[total - 1] << endl;
  return 0;
}
