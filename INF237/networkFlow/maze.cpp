// =============================================================
// MAZE — Edmonds-Karp Maximum Flow
// =============================================================
//
// PROBLEM: Given n rooms with integer values, two rooms can have a
//          connecting passage if gcd(room[i], room[j]) > 1.
//          The capacity of the passage = gcd.
//          Rooms are sorted; find max flow from room[0] to room[n-1].
//
// ALGORITHM: Edmonds-Karp (BFS-based Max Flow)
//   Edmonds-Karp is Ford-Fulkerson where the augmenting path is always
//   found with BFS (shortest path in terms of number of edges).
//   This guarantees O(VE^2) time regardless of capacity values.
//
// KEY CONCEPTS:
//
//   RESIDUAL GRAPH:
//     cap[u][v] = residual capacity from u to v.
//     Forward edges start at gcd capacity and decrease as flow is pushed.
//     Backward edges start at 0 and increase, allowing flow to be "cancelled".
//
//   AUGMENTING PATH:
//     A path from source to sink in the residual graph (where all cap > 0).
//     BFS finds the SHORTEST such path (fewest edges).
//
//   FLOW AUGMENTATION:
//     Find bottleneck = min cap on the path.
//     Push that much flow: decrease forward caps, increase backward caps.
//
//   MAX-FLOW MIN-CUT THEOREM:
//     The algorithm terminates when BFS finds no path → maximum flow found.
//     This equals the minimum cut (min total capacity of edges to remove to disconnect s from t).
//
// DIAGRAM:
//   Source (s=0) → [intermediate nodes] → Sink (t=n-1)
//
//   Each BFS finds a shortest augmenting path, pushes flow, updates residuals.
//   Repeat until no path exists.
//
// TIME: O(VE^2)  where V=n rooms, E=number of passages (pairs with gcd>1)
// =============================================================

#include <algorithm>
#include <bits/stdc++.h>
#include <utility>

using namespace std;

int n;
vector<vector<int>> cap(1001, vector<int>(1001, 0)); // residual capacity matrix
int bfs(int s, int t, vector<int> &parent);
vector<int> rooms;

int solve(int s, int t);

int main() {

  cin >> n;
  rooms.resize(n);

  for (int i = 0; i < n; i++) {
    cin >> rooms[i];
  }

  // Sort rooms: smallest = entrance (source), largest = exit (sink)
  sort(rooms.begin(), rooms.end());

  // Build the graph: connect rooms that share a common factor (gcd > 1)
  // Edge capacity = gcd (flow rate through the shared passage)
  for (int i = 0; i < n; i++) {
    for (int j = i + 1; j < n; j++) {
      int gcd = __gcd(rooms[i], rooms[j]);
      if (gcd > 1) {
        cap[i][j] += gcd; // forward: i → j
        cap[j][i] += gcd; // forward: j → i (undirected passage)
      }
    }
  }

  int sol = solve(0, n - 1); // source = index 0, sink = index n-1
  cout << sol << endl;

  return 0;
}

// BFS: find shortest augmenting path from s to t in the residual graph.
// parent[v] = which node we came from to reach v.
// Returns the bottleneck flow on the found path, or 0 if no path exists.
int bfs(int s, int t, vector<int> &parent) {
  fill(parent.begin(), parent.end(), -1); // -1 = not visited
  parent[s] = s; // source: parent points to itself (marks as visited)
  queue<pair<int, int>> q; // {node, bottleneck so far}
  q.push({s, INT_MAX}); // start with "unlimited" capacity; edges will reduce it

  while (!q.empty()) {
    auto [u, flow] = q.front();
    q.pop();

    for (int v = 0; v < n; v++) {
      if (parent[v] == -1 && cap[u][v] > 0) { // unvisited, residual capacity > 0
        parent[v] = u;
        int new_flow = min(flow, cap[u][v]); // bottleneck = min along path
        if (v == t) return new_flow; // reached sink: return bottleneck
        q.push({v, new_flow});
      }
    }
  }
  return 0; // no path to sink
}

// Edmonds-Karp: repeatedly find augmenting paths via BFS and push flow.
int solve(int s, int t) {
  int tot_flow = 0;
  vector<int> parent(n);

  int pushed;
  while ((pushed = bfs(s, t, parent)) > 0) {
    tot_flow += pushed;

    // Walk backwards from t to s, update residual capacities
    int v = t;
    while (v != s) {
      int u = parent[v];
      cap[u][v] -= pushed; // forward edge: capacity reduced by flow pushed
      cap[v][u] += pushed; // backward edge: capacity increased (flow can be undone)
      v = u;
    }
    // Backward edges allow future BFS to "reroute" flow for better paths
  }

  return tot_flow; // = max flow (= min cut by max-flow min-cut theorem)
}
