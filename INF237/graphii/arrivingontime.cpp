// =============================================================
// ARRIVING ON TIME — Modified Dijkstra for Latest Departure
// =============================================================
//
// PROBLEM: Bus/train network where each connection runs on a fixed
//          schedule. You must arrive at the destination (stop n-1) by
//          time s. Find the LATEST time you can LEAVE stop 0.
//
// EDGE (u → v): departs from u at times t0, t0+p, t0+2p, ...
//               and arrives at v exactly d minutes later.
//               So: departure times = t0, t0+p, ...
//                   arrival times   = t0+d, t0+p+d, ...
//
// KEY INSIGHT — Run Dijkstra BACKWARDS:
//   Instead of "earliest arrival at v", compute "latest departure from u"
//   that still gets you to n-1 by time s.
//   Start from the destination with latest[n-1] = s (you CAN be there at s).
//   Propagate backwards: for each node v with known latest arrival time,
//   find the latest departure from any u that feeds v on time.
//
// FINDING LATEST VALID DEPARTURE:
//   If latest[v] = T (latest you can arrive at v), and edge u→v has:
//     - first arrival at v: firstArrival = t0 + d
//     - arrivals at v are periodic: firstArrival, firstArrival + p, ...
//   We want the LATEST arrival ≤ T. Using integer division:
//     arrival = firstArrival + floor((T - firstArrival) / p) * p
//   Then: departure from u = arrival - d
//
// DIAGRAM:
//
//   [stop 0] --edge(u→v)--> [stop v] --...--> [stop n-1]
//                 schedule: t0, t0+p, t0+2p, ...
//
//   Backwards Dijkstra from n-1:
//   latest[n-1] = s
//   For each edge into v: compute latest departure from u → update latest[u]
//
// TIME: O((V + E) log V)  — standard Dijkstra with priority queue
// =============================================================

#include <iostream>
#include <queue>
#include <vector>

using namespace std;

struct Edge {
  int from;     // origin stop (u) of this connection
  long long t0; // time of FIRST arrival at destination v
  long long p;  // period between consecutive trips (frequency)
  long long d;  // travel duration from u to v (d minutes)
};

int main(int argc, char *argv[]) {
  int n, m;
  long long s; // deadline: must be at stop n-1 by time s (can be up to 1e9)
  cin >> n >> m >> s;

  // adj[v] = list of edges that ARRIVE at v (reverse graph for backwards Dijkstra)
  vector<vector<Edge>> adj(n);
  for (int i = 0; i < m; i++) {
    int u, v, t0, p, d;
    cin >> u >> v >> t0 >> p >> d;
    // Edge goes u → v, so store in adj[v] for reverse traversal
    adj[v].push_back({u, t0, p, d});
  }

  // latest[i] = latest time you can depart from stop i and still make it
  // -1 means "not yet determined / unreachable"
  priority_queue<pair<long long, int>> pq; // max-heap: {latest_departure, node}
  vector<long long> latest(n, -1);
  latest[n - 1] = s; // at the destination, the deadline is s
  pq.push({s, n - 1});

  while (!pq.empty()) {
    long long time = pq.top().first;  // latest time we can be at 'to'
    int to = pq.top().second;
    pq.pop();

    // Skip stale entries (we already found a better/later time for 'to')
    if (time < latest[to]) {
      continue;
    }

    // For each edge e that arrives at 'to' (i.e., e.from → to):
    for (Edge e : adj[to]) {
      // The first possible arrival at 'to' from this edge
      long long firstArrival = e.t0 + e.d;

      // If we need to be at 'to' before even the first arrival → skip
      if (time < firstArrival) {
        continue;
      }

      // Find the LATEST arrival at 'to' that is still ≤ 'time'
      // arrivals happen at: firstArrival, firstArrival+p, firstArrival+2p, ...
      // floor((time - firstArrival) / p) gives how many full periods fit
      long long arrival = firstArrival + ((time - firstArrival) / e.p) * e.p;

      // The corresponding departure from e.from = arrival - travel time
      long long departure = arrival - e.d;

      // Update if we found a later departure for e.from
      if (departure > latest[e.from]) {
        latest[e.from] = departure;
        pq.push({departure, e.from});
      }
    }
  }

  if (latest[0] == -1) {
    cout << "impossible" << endl; // can't reach n-1 from stop 0 in time
  } else {
    cout << latest[0]; // latest departure time from stop 0
  }

  return 0;
}
