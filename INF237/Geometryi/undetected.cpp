// =============================================================
// UNDETECTED — Sensor Coverage using DSU (Disjoint Set Union)
// =============================================================
//
// PROBLEM: N circular sensors on a 200×200 grid. A target moves from
//          top to bottom (y decreasing). It is detected if it must pass
//          through the UNION of all sensor discs.
//
// KEY INSIGHT: The target can pass undetected if and only if there is a
//              "gap" — a path through the sensor field from left (x=0) to
//              right (x=200) that is NOT covered by any combination of
//              overlapping sensors.
//
//              This is equivalent to: can sensors form a connected chain
//              from the LEFT wall to the RIGHT wall?
//              If LEFT and RIGHT are in the same DSU component → target is detected.
//
// DSU TRICK — Virtual Nodes:
//   Add two virtual nodes:
//     LEFT  = N   (represents the left wall, x=0)
//     RIGHT = N+1 (represents the right wall, x=200)
//   A sensor k touches the LEFT wall if  s[k].x - s[k].radius <= 0
//   A sensor k touches the RIGHT wall if s[k].x + s[k].radius >= 200
//   Two sensors i, j overlap if dist(i,j) <= radius_i + radius_j
//
// ALGORITHM: Process sensors one by one. After adding each sensor:
//   1. Check overlap with all previously added sensors → union if overlapping
//   2. Check if sensor touches LEFT wall → union with LEFT
//   3. Check if sensor touches RIGHT wall → union with RIGHT
//   4. If find(LEFT) == find(RIGHT) → barrier formed! → output k (0-indexed)
//
// If we process all N sensors without LEFT and RIGHT unifying → output N (undetected always).
//
// DSU (Union-Find) with path compression and union by rank:
//   - find(x): returns root of x's component (with path compression for O(α) amortised)
//   - unionSet(x,y): merge components by rank (smaller tree under larger)
//
// DIAGRAM:
//   [LEFT wall]  s0  s1  s2  [RIGHT wall]
//   If s0 and s2 overlap, and s2 touches right → chain: LEFT-s0-s2-RIGHT
//   → detected after adding s2.
//
// TIME: O(N² · α(N))  — N² overlap checks, each DSU op is nearly O(1)
// =============================================================

#include <iostream>
#include <vector>

using namespace std;

struct DSU {
  vector<int> parent;
  vector<int> rank; // upper bound on tree depth (used for union by rank)

  DSU(int n) {
    parent.resize(n);
    rank.resize(n);
    for (int i = 0; i < n; i++) {
      parent[i] = i; // each element is its own root initially
      rank[i] = 0;   // all trees start with depth 0
    }
  }

  // find with PATH COMPRESSION:
  //   If parent[x] != x, recursively find the root and then point x directly
  //   to the root (flattening the tree for future lookups).
  int find(int x) {
    if (parent[x] != x) {
      parent[x] = find(parent[x]); // path compression
    }
    return parent[x];
  }

  // UNION BY RANK:
  //   Always attach the smaller-rank tree under the larger-rank tree.
  //   If equal rank, pick one and increment its rank.
  //   This keeps tree depth logarithmic → O(log n) without path compression.
  void unionSet(int x, int y) {
    x = find(x);
    y = find(y);
    if (x == y) return; // already in the same component

    // Attach smaller-rank root under larger-rank root
    if (rank[x] < rank[y]) {
      parent[x] = y;
    } else if (rank[x] > rank[y]) {
      parent[y] = x;
    } else {
      // Equal rank: pick x as new root, increment its rank
      parent[y] = x;
      rank[x]++;
    }
  }
};

struct sensor {
  double x;
  double y;
  double radius;
};

int main() {

  int N;
  cin >> N;

  vector<sensor> s(N);

  for (int i = 0; i < N; i++)
    cin >> s[i].x >> s[i].y >> s[i].radius;

  // Virtual nodes: LEFT = N, RIGHT = N+1
  int LEFT  = N;
  int RIGHT = N + 1;
  DSU dsu(N + 2); // N sensors + 2 virtual wall nodes

  // Add sensors one at a time, stopping as soon as LEFT-RIGHT bridge forms
  for (int k = 0; k < N; k++) {
    // Check overlap with all EARLIER sensors
    for (int j = 0; j < k; j++) {
      long long dx = s[k].x - s[j].x;
      long long dy = s[k].y - s[j].y;
      long long dist = dx * dx + dy * dy; // squared distance (avoid sqrt)
      long long rr = (long long)(s[k].radius + s[j].radius) * (s[k].radius + s[j].radius);

      if (dist <= rr) // circles overlap or touch → they form a connected barrier
        dsu.unionSet(k, j);
    }

    // Check if sensor k touches the LEFT wall (x=0)
    if (s[k].x - s[k].radius <= 0)
      dsu.unionSet(k, LEFT);

    // Check if sensor k touches the RIGHT wall (x=200)
    if (s[k].x + s[k].radius >= 200)
      dsu.unionSet(k, RIGHT);

    // After adding sensor k, is there now a full LEFT-to-RIGHT barrier?
    if (dsu.find(LEFT) == dsu.find(RIGHT)) {
      cout << k << "\n"; // k sensors (0-indexed) were enough to block
      return 0;
    }
  }

  // All N sensors added, still no barrier → always undetected
  cout << N << "\n";
}
