// =============================================================
// GET SHORTY — Modified Dijkstra for Maximum Probability Path
// =============================================================
//
// PROBLEM: Graph where each edge has a "survival probability" weight
//          (a decimal between 0 and 1). Find the path from node 0 to
//          node n-1 that MAXIMISES the product of edge weights.
//
// IDEA: Use Dijkstra, but instead of minimising total distance,
//       MAXIMISE the product of probabilities.
//
// CHANGE FROM STANDARD DIJKSTRA:
//   - dist[v] = maximum probability of reaching v from source
//   - Initialise dist[0] = 1.0 (100% chance at start)
//   - Relaxation: if dist[u] * weight(u,v) > dist[v], update dist[v]
//   - Priority queue is a MAX-heap (normal: min-heap)
//   - Skip stale entries where weight < dist[node] (not just !=)
//
// WHY NOT LOG-SUM? Could also convert to -log(weight) and minimise sum,
//   but the direct multiplication approach is equally valid and simpler.
//
// DIAGRAM:
//   0 --0.5-- 1 --0.8-- 2
//   0 --0.9-- 2
//   Best path 0→2: direct 0.9 vs 0→1→2 = 0.5*0.8=0.4 → answer: 0.9000
//
// TIME: O((V + E) log V)
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
  double weight; // probability of surviving this edge (0 to 1)
};

struct Node {
  int id;
  vector<Edge> edges;
};

// Max-heap comparator for edges: prefer SMALLER weight (for min-heap behaviour in std::pq)
// But wait — we WANT a max-heap for probabilities.
// std::priority_queue is a max-heap by default.
// This comparator: returns true when a < b, making pq give the LARGEST element first.
// Actually: pq uses this to say "a is less than b", so the largest priority_queue.top().
class Compare {
public:
  bool operator()(Edge a, Edge b) {
    if (a.weight < b.weight) {
      return true; // b has higher weight → b should come out first (max-heap)
    }
    return false;
  }
};

int main() {
  cout << setprecision(4) << fixed;

  while (true) {
    int n, m;
    cin >> n >> m;
    if (n == 0 && m == 0) {
      break; // sentinel: input ends with "0 0"
    }
    vector<vector<Edge>> edges(n); // adjacency list

    for (int i = 0; i < m; i++) {
      int a, b;
      double weight;
      cin >> a >> b >> weight;
      Edge e = {a, b, weight};
      edges[a].push_back(e); // undirected: add both directions
      edges[b].push_back(e);
    }

    // dist[v] = best (maximum) probability of reaching v from node 0
    priority_queue<pair<double, int>> pq; // max-heap: {probability, node}
    vector<double> dist(n, 0);
    vector<bool> visited(n, false);
    dist[0] = 1; // start at node 0 with probability 1.0
    pq.push({dist[0], 0});

    while (!pq.empty()) {
      auto current = pq.top();
      pq.pop();
      double weight = current.first; // current best probability
      int b = current.second;        // current node

      // Skip stale entries (we already found a better path to b)
      if (weight < dist[b]) {
        continue;
      }

      // Relax all edges from b
      for (auto edge : edges[b]) {
        int a = edge.a;
        int next = (a == b) ? edge.b : a; // find the other endpoint

        // New candidate probability = current probability × edge weight
        double candidate = dist[b] * edge.weight;
        if (candidate > dist[next]) {
          dist[next] = candidate;
          pq.push({dist[next], next}); // push updated probability
        }
      }
    }

    cout << dist[n - 1] << endl; // best probability of reaching node n-1
  }
  return 0;
}
