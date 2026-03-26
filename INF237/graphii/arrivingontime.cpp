#include <iostream>
#include <queue>
#include <vector>

using namespace std;

struct Edge {
  int from;
  long long t0;
  long long p;
  long long d;
};

// weight = timeto train + time to dist
// t0 = fist
// u = origin
// v = destination
// p = freq
// d = time

// hotel = stop 0
// meet = stop n-1

int main(int argc, char *argv[]) {
  int n, m;
  long long s; // s mulig 1e9
  cin >> n >> m >> s;
  vector<vector<Edge>> adj(n);
  for (int i = 0; i < m; i++) {
    int u, v, t0, p, d;
    cin >> u >> v >> t0 >> p >> d;
    adj[v].push_back({u, t0, p, d});
  }

  priority_queue<pair<long long, int>> pq;
  vector<long long> latest(n, -1);
  latest[n - 1] = s;
  pq.push({s, n - 1});
  while (!pq.empty()) {
    long long time = pq.top().first;
    int to = pq.top().second;
    pq.pop();

    if (time < latest[to]) {
      continue;
    }

    for (Edge e : adj[to]) {
      long long firstArrival = e.t0 + e.d;

      if (time < firstArrival) { // på stoppet for tidlig
        continue;
      }

      // finner "forrige" arrive på stoppet
      long long arrival = firstArrival + ((time - firstArrival) / e.p) * e.p;
      long long departure = arrival - e.d;

      if (departure > latest[e.from]) {
        latest[e.from] = departure;
        pq.push({departure, e.from});
      }
    }
  }

  if (latest[0] == -1) {
    cout << "impossible" << endl;
  } else {
    cout << latest[0];
  }

  return 0;
}
