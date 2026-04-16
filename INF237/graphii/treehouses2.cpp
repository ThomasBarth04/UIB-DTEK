// =============================================================
// TREEHOUSES 2 — Minimum Spanning Tree with Zero-Cost Edges (Prim's)
// =============================================================
//
// PROBLEM: You have n nodes on a 2D plane. Some pairs are already
//          connected (cost 0 — pre-built paths/platforms). Remaining
//          pairs can be connected at cost = Euclidean distance.
//          Find the total cost of the minimum spanning tree (MST).
//
// ALGORITHM: Prim's MST (simple O(n²) version — good enough for dense graphs)
//
//   Prim's idea:
//   - Start with any node in the MST. Grow it one node at a time.
//   - dists[v] = cheapest edge cost to add v to the MST.
//   - At each step: pick the non-MST node with the smallest dists[],
//                   add it (add its edge cost to sum), then update
//                   dists[] for all neighbors of the newly added node.
//
// DIAGRAM (3 nodes: 0-1-2 in a line):
//
//   Initially: dists = [0, INF, INF],  inmst = [F, F, F]
//   Step 1: pick node 0 (cheapest non-MST). sum += 0. inmst[0]=T.
//           Update: dists[1] = dist(0,1), dists[2] = dist(0,2)
//   Step 2: pick node 1 (closer). sum += dist(0,1). inmst[1]=T.
//           Update: dists[2] = min(dists[2], dist(1,2))
//   Step 3: pick node 2. sum += dist(1,2). Done.
//
// SPECIAL CASE: zeroEdges[i][j] = true → edge (i,j) has cost 0.
//   This handles pre-built connections (no cost to connect those nodes).
//
// TIME: O(n² + e)  where e = pre-built edges
// =============================================================

#include <cmath>
#include <iostream>
#include <vector>

using namespace std;

struct Node {
  double x;  // x-coordinate on the 2D plane
  double y;  // y-coordinate
  int id;    // node index
};

int main(int argc, char *argv[]) {
  int n, e, p;
  cin >> n >> e >> p;
  // n = total nodes, e = nodes in the "platform cluster" (zero-cost among them),
  // p = additional zero-cost edge pairs

  vector<Node> nodes(n);
  // zeroEdges[i][j] = true means connecting i and j costs 0
  vector<vector<bool>> zeroEdges(n, vector<bool>(n, false));

  for (int i = 0; i < n; i++) {
    Node node;
    cin >> node.x >> node.y;
    node.id = i;
    nodes[i] = node; // store by value (fixed from treehouses.cpp which stored dangling pointers)
  }

  // All nodes in the first 'e' group are mutually connected for free
  for (int i = 0; i < e; i++) {
    for (int j = i + 1; j < e; j++) {
      zeroEdges[i][j] = true;
      zeroEdges[j][i] = true;
    }
  }

  // Additional zero-cost edges from input (1-indexed, so subtract 1)
  for (int i = 0; i < p; i++) {
    int a, b;
    cin >> a >> b;
    a--;
    b--;
    zeroEdges[a][b] = true;
    // Note: only one direction set here (possible asymmetry bug vs treehouses.cpp)
  }

  // ── Prim's MST ───────────────────────────────────────────────────────
  vector<bool> inmst(n, false);         // is node in MST yet?
  vector<double> dists(n, INFINITY);   // cheapest edge cost to join MST
  dists[0] = 0;                         // start from node 0 with cost 0

  double sum = 0; // total MST cost
  for (int i = 0; i < n; i++) {
    // Find the non-MST node with the smallest known edge cost (greedy pick)
    int pick = -1;
    for (int j = 0; j < n; j++) {
      if (!inmst[j] && (pick == -1 || dists[j] < dists[pick])) {
        pick = j;
      }
    }
    // Add pick to the MST
    sum += dists[pick];
    inmst[pick] = true;

    // Update dists[] for all non-MST neighbors of the newly added node
    for (int g = 0; g < n; g++) {
      if (inmst[g]) continue; // already in MST, skip

      double dist;
      if (zeroEdges[pick][g]) {
        dist = 0; // pre-built: free to connect
      } else {
        // Euclidean distance: sqrt((dx)^2 + (dy)^2)
        // hypot() is equivalent to sqrt(dx*dx + dy*dy) but more numerically stable
        dist = hypot(nodes[pick].x - nodes[g].x, nodes[pick].y - nodes[g].y);
      }

      if (dist < dists[g]) {
        dists[g] = dist; // found a cheaper way to connect g → update
      }
    }
  }
  cout << sum << endl; // total MST cost

  return 0;
}
