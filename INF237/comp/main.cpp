// =============================================================
// ERRANDS (comp version) — TSP via Bitmask DP (Cleaner Implementation)
// =============================================================
//
// Same algorithm as DynamicProgrammingII/errands.cpp — Held-Karp TSP.
// This version is a cleaner rewrite:
//   - Uses unordered_map<string, int> for name→id lookup (faster than map)
//   - Processes multiple tasks per input (one line per task, empty line separates nothing)
//   - Stores all location points in a flat vector<Point> (no map lookup in hot loop)
//
// See DynamicProgrammingII/errands.cpp for the full algorithm explanation and diagrams.
//
// KEY DIFFERENCES:
//   1. Location names mapped to integer IDs up front (id["work"], id["home"])
//   2. between[i][j], fromWork[i], toHome[i] precomputed for each task's stops
//   3. parent[][] array tracks which stop was visited before each (mask, stop) state
//      (enables path reconstruction)
//   4. Skips empty lines instead of breaking on them
//
// DP RECAP:
//   dp[mask][last] = min distance starting from work, visiting all stops in mask,
//                    ending at stop 'last'.
//   Base:  dp[1<<i][i] = dist(work, stop_i)
//   Trans: dp[mask|(1<<nxt)][nxt] = min(dp[mask][last] + dist(last, nxt))
//   Final: min over last of dp[FULL-1][last] + dist(last, home)
// =============================================================

#include <bits/stdc++.h>
using namespace std;

struct Point {
  double x;
  double y;
};

// Euclidean distance between two points
static double dist(const Point &a, const Point &b) {
  double dx = a.x - b.x;
  double dy = a.y - b.y;
  return sqrt(dx * dx + dy * dy);
}

int main() {
  ios::sync_with_stdio(false);
  cin.tie(nullptr);

  int n;
  if (!(cin >> n)) return 0; // number of named locations

  unordered_map<string, int> id; // location name → index
  vector<string> names(n);
  vector<Point> points(n);

  for (int i = 0; i < n; ++i) {
    cin >> names[i] >> points[i].x >> points[i].y;
    id[names[i]] = i;
  }

  const int work = id["work"];
  const int home = id["home"];

  string line;
  getline(cin, line); // consume newline after location list

  constexpr double INF = 1e100;

  // Process each task (one line = one set of errands)
  while (getline(cin, line)) {
    if (line.empty()) continue; // skip blank lines

    istringstream iss(line);
    vector<string> stops;
    string stop;
    while (iss >> stop) stops.push_back(stop);

    int m = (int)stops.size(); // number of errands in this task
    vector<int> stopIds(m);
    for (int i = 0; i < m; ++i) {
      stopIds[i] = id[stops[i]]; // resolve name → point index
    }

    // Precompute distances for this task
    vector<double> fromWork(m), toHome(m);
    vector<vector<double>> between(m, vector<double>(m, 0.0));
    for (int i = 0; i < m; ++i) {
      fromWork[i] = dist(points[work], points[stopIds[i]]);
      toHome[i]   = dist(points[stopIds[i]], points[home]);
      for (int j = 0; j < m; ++j) {
        between[i][j] = dist(points[stopIds[i]], points[stopIds[j]]);
      }
    }

    int fullMask = 1 << m; // 2^m subsets

    // dp[mask][last] = min distance from work, visiting stops in mask, ending at 'last'
    vector<vector<double>> dp(fullMask, vector<double>(m, INF));
    // parent[mask][last] = which stop came before 'last' in the optimal path to (mask, last)
    vector<vector<int>> parent(fullMask, vector<int>(m, -1));

    // Base case: go from work to a single stop as first errand
    for (int i = 0; i < m; ++i) {
      dp[1 << i][i] = fromWork[i];
    }

    // Fill DP: extend each partial path to an unvisited stop
    for (int mask = 1; mask < fullMask; ++mask) {
      for (int last = 0; last < m; ++last) {
        if (!(mask & (1 << last))) continue;  // 'last' not in mask
        if (dp[mask][last] >= INF / 2) continue; // unreachable

        for (int nxt = 0; nxt < m; ++nxt) {
          if (mask & (1 << nxt)) continue; // 'nxt' already visited

          int nextMask = mask | (1 << nxt);
          double cand = dp[mask][last] + between[last][nxt];
          if (cand < dp[nextMask][nxt]) {
            dp[nextMask][nxt] = cand;
            parent[nextMask][nxt] = last; // record predecessor
          }
        }
      }
    }

    // Find which final stop minimises total distance (including home leg)
    int bestLast = 0;
    double bestCost = INF;
    int doneMask = fullMask - 1; // all stops visited
    for (int last = 0; last < m; ++last) {
      double total = dp[doneMask][last] + toHome[last];
      if (total < bestCost) {
        bestCost = total;
        bestLast = last;
      }
    }

    // Reconstruct path by following parent pointers backwards
    vector<int> order;
    int mask = doneMask;
    int cur = bestLast;
    while (cur != -1) {
      order.push_back(cur);
      int prev = parent[mask][cur];
      mask ^= 1 << cur; // remove cur from mask (trace backwards)
      cur = prev;
    }
    reverse(order.begin(), order.end()); // path was collected backwards

    // Print optimal errand order
    for (int i = 0; i < m; ++i) {
      if (i) cout << ' ';
      cout << stops[order[i]];
    }
    cout << '\n';
  }

  return 0;
}
