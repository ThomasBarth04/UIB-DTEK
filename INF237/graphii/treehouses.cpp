// =============================================================
// TREEHOUSES — Minimum Spanning Tree with Zero-Cost Edges (Prim's)
//              FIRST VERSION — uses pointers (has a bug: dangling pointer)
// =============================================================
//
// See treehouses2.cpp for the corrected version that stores Node by value.
//
// BUG HERE: `nodes[i] = &node;` — node is a stack variable declared inside
// the loop body. After the loop iteration ends, node goes out of scope, so
// nodes[i] holds a dangling pointer. Using nodes[i] later is undefined behaviour.
//
// ALGORITHM: Prim's MST — see treehouses2.cpp for full explanation.
//
// DIFFERENCE FROM treehouses2.cpp:
//   - Uses pointers (Node*) instead of values (Node) → causes the dangling bug
//   - Sets zeroEdges both directions in the platform cluster
//   - Also prints each computed Euclidean distance (debug output)
// =============================================================

#include <cmath>
#include <iostream>
#include <vector>

using namespace std;

struct Node {
  double x;  // x-coordinate
  double y;  // y-coordinate
  int id;    // node index
};

int main(int argc, char *argv[]) {
  int n, e, p;
  cin >> n >> e >> p;

  vector<Node *> nodes(n); // BUG: will store dangling pointers
  vector<vector<bool>> zeroEdges(n, vector<bool>(n, false));

  for (int i = 0; i < n; i++) {
    Node node;            // stack-allocated — destroyed at end of this iteration
    cin >> node.x >> node.y;
    node.id = i;
    nodes[i] = &node;    // DANGLING POINTER after loop body ends!
  }

  // Mark the first e nodes as mutually zero-cost (pre-built platform)
  for (int i = 0; i < e; i++) {
    for (int j = i + 1; j < e; j++) {
      zeroEdges[i][j] = true;
      zeroEdges[j][i] = true; // symmetric (both directions)
    }
  }

  // Additional zero-cost edges (1-indexed input)
  for (int i = 0; i < p; i++) {
    int a, b;
    cin >> a >> b;
    a--;
    b--;
    zeroEdges[a][b] = true;
    zeroEdges[b][a] = true; // both directions
  }

  // ── Prim's MST ───────────────────────────────────────────────────────
  vector<bool> inmst(n, false);
  vector<double> dists(n, INFINITY);
  dists[0] = 0;

  double sum = 0;
  for (int i = 0; i < n; i++) {
    // Greedy pick: non-MST node with smallest edge cost
    int pick = -1;
    for (int j = 0; j < n; j++) {
      if (!inmst[j] && (pick == -1 || dists[j] < dists[pick])) {
        pick = j;
      }
    }
    sum += dists[pick];
    inmst[pick] = true;

    // Relax edges from pick to all non-MST nodes
    for (int g = 0; g < n; g++) {
      if (inmst[g]) continue;

      double dist;
      if (zeroEdges[pick][g]) {
        dist = 0;
      } else {
        // Dereference pointers — undefined behaviour due to dangling pointers above
        Node pickNode = *nodes[pick];
        Node gNode = *nodes[g];
        dist = hypot(pickNode.x - gNode.x, pickNode.y - gNode.y);
        cout << dist << endl; // debug print (not in treehouses2.cpp)
      }

      if (dist < dists[g]) {
        dists[g] = dist;
      }
    }
  }
  cout << sum << endl;

  return 0;
}
