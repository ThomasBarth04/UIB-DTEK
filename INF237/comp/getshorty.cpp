// =============================================================
// GET SHORTY — Modified Dijkstra for Maximum Probability Path
// =============================================================
//
// PROBLEM: A graph where each edge has a "survival probability" weight
//          (0 < weight ≤ 1). Find the path from node 0 to node n-1 that
//          maximises the PRODUCT of edge weights along the path.
//
// ALGORITHM: Modified Dijkstra with maximisation instead of minimisation.
//
//   Standard Dijkstra minimises sum of distances.
//   Here we MAXIMISE product of probabilities.
//
// CHANGES FROM STANDARD DIJKSTRA:
//   - dist[v] = MAXIMUM product-probability to reach v from node 0
//   - dist[0] = 1.0  (certainty at the start)
//   - Relaxation: if dist[u] * edge.weight > dist[v] → update dist[v]
//   - priority_queue gives the node with HIGHEST probability first
//     (max-heap, which is the C++ default for priority_queue)
//   - Skip stale entries where current prob < dist[node]
//
// EXAMPLE:
//   0 --0.5-- 1 --0.8-- 2
//   0 --0.9-- 2
//   Path 0→2 direct: 0.9000
//   Path 0→1→2: 0.5 * 0.8 = 0.4000
//   Answer: 0.9000
//
// INPUT FORMAT: Multiple test cases, each starting with n m.
//   Terminate with "0 0".
//
// TIME: O((V + E) log V)  — same as standard Dijkstra
// =============================================================

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <queue>
#include <vector>
using namespace std;

struct Edge {
  int a;
  int b;
  double weight; // survival probability of this edge
};

struct Node {
  int id;
  vector<Edge> edges;
};

// Comparator for the priority queue.
// Standard pq is a max-heap. This comparator makes "smaller weight = higher priority",
// which inverts to give us min-heap behaviour by weight.
// But here we WANT max-heap by probability → use the default less<> on pair<double,int>.
class Compare {
public:
  bool operator()(Edge a, Edge b) {
    if (a.weight < b.weight) {
      return true; // a has smaller weight → b should come out of pq first (max-heap)
    }
    return false;
  }
};

int main() {
  cout << setprecision(4) << fixed;

  while (true) {
    int n, m;
    cin >> n >> m;
    if (n == 0 && m == 0) break; // sentinel

    vector<vector<Edge>> edges(n); // adjacency list

    for (int i = 0; i < m; i++) {
      int a, b;
      double weight;
      cin >> a >> b >> weight;
      Edge e = {a, b, weight};
      edges[a].push_back(e); // undirected graph
      edges[b].push_back(e);
    }

    // dist[v] = best (maximum) probability to reach v from node 0
    priority_queue<pair<double, int>> pq; // max-heap: {probability, node}
    vector<double> dist(n, 0);
    vector<bool> visited(n, false);
    dist[0] = 1; // start with probability 1 at node 0
    pq.push({dist[0], 0});

    while (!pq.empty()) {
      auto current = pq.top();
      pq.pop();
      double weight = current.first; // best probability to reach this node
      int b = current.second;

      // Skip stale entries (we found a better path to b already)
      if (weight < dist[b]) {
        continue;
      }

      // Relax all edges from b
      for (auto edge : edges[b]) {
        int a = edge.a;
        int next = (a == b) ? edge.b : a; // get the OTHER endpoint

        // New candidate = probability to b * edge weight
        double candidate = dist[b] * edge.weight;
        if (candidate > dist[next]) {
          dist[next] = candidate; // found a better path to next
          pq.push({dist[next], next});
        }
      }
    }

    // Print the maximum probability to reach the last node
    cout << dist[n - 1] << endl;
  }
  return 0;
}
