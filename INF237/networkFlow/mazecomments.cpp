#include <algorithm>
#include <bits/stdc++.h>
#include <utility>
using namespace std;

// n = number of rooms
// cap[u][v] = residual capacity from node u to node v.
// Starts as the edge's original capacity, then shrinks as flow is pushed.
// Backward edges (cap[v][u]) start at 0 and grow — they let us "undo" flow
// later.
int n;
vector<vector<int>> cap(1001, vector<int>(1001, 0));
vector<int> rooms;

// Forward declarations so main() can call solve/bfs defined below
int bfs(int s, int t, vector<int> &parent);
int solve(int s, int t);

int main() {
  cin >> n;
  rooms.resize(n); // MUST resize here — n was 0 at global init time

  for (int i = 0; i < n; i++)
    cin >> rooms[i];

  // Sort so rooms[0] = entrance (smallest), rooms[n-1] = exit (largest)
  sort(rooms.begin(), rooms.end());

  // Build the graph.
  // Two rooms get an edge if gcd > 1 (they share a common factor).
  // The edge capacity = gcd (people per minute that can pass).
  // Both directions get the same capacity because passages are two-way.
  // j = i+1 avoids processing each pair twice and avoids self-loops (i==i).
  for (int i = 0; i < n; i++) {
    for (int j = i + 1; j < n; j++) {
      int gcd = __gcd(rooms[i], rooms[j]);
      if (gcd > 1) { // gcd==1 means coprime — no shared factor, no passage
        cap[i][j] += gcd;
        cap[j][i] += gcd;
      }
    }
  }

  // Source = index 0 (smallest room = entrance)
  // Sink   = index n-1 (largest room = exit)
  int sol = solve(0, n - 1);
  cout << sol << endl;
  return 0;
}

// BFS finds the SHORTEST augmenting path from s to t (fewest edges).
// Using BFS instead of DFS is what makes this Edmonds-Karp specifically,
// and gives the O(VE^2) guarantee regardless of capacity values.
//
// parent[v] = which node we came from to reach v.
// This lets us reconstruct the full path once we reach t.
//
// Returns the bottleneck (max flow pushable along this path), or 0 if no path.
int bfs(int s, int t, vector<int> &parent) {
  fill(parent.begin(), parent.end(), -1); // -1 = unvisited
  parent[s] =
      s; // source points to itself (marks it visited, signals path start)

  // Queue holds {current node, bottleneck flow so far on this path}
  queue<pair<int, int>> q;
  q.push(
      {s, INT_MAX}); // start with "infinite" capacity, edges will constrain it

  while (!q.empty()) {
    auto [u, flow] = q.front();
    q.pop();

    for (int v = 0; v < n; v++) {
      // Only visit unvisited nodes with remaining residual capacity
      if (parent[v] == -1 && cap[u][v] > 0) {
        parent[v] = u;
        int new_flow = min(flow, cap[u][v]); // bottleneck shrinks at each step

        if (v == t)
          return new_flow; // reached sink — return bottleneck immediately

        q.push({v, new_flow});
      }
    }
  }
  return 0; // no path to t exists — algorithm is done
}

// Edmonds-Karp: repeatedly find augmenting paths via BFS and push flow.
// Stops when BFS can no longer reach t — that means we've hit the max flow.
int solve(int s, int t) {
  int tot_flow = 0;
  vector<int> parent(n);
  int pushed;

  while ((pushed = bfs(s, t, parent)) > 0) {
    tot_flow += pushed;

    // Walk BACKWARDS from t to s using parent[] to retrace the path BFS found.
    // Update the residual graph along every edge on the path.
    int v = t;
    while (v != s) {
      int u = parent[v];
      cap[u][v] -= pushed; // forward edge: we used some capacity
      cap[v][u] += pushed; // backward edge: we can now "undo" this flow later
      v = u;
    }
    // Why backward edges matter: if a later BFS finds that the flow we pushed
    // here was suboptimal, it can route flow backwards through cap[v][u]
    // to effectively reroute it — without needing to track flow separately.
  }

  return tot_flow; // = max flow = min cut (by the max-flow min-cut theorem)
}
