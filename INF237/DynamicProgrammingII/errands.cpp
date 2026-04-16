// =============================================================
// ERRANDS — Travelling Salesman Problem (TSP) via Bitmask DP
// =============================================================
//
// PROBLEM: Starting from "work", visit a set of errand locations,
//          then return to "home". Find the shortest total distance.
//          Must visit ALL errands (in optimal order).
//
// ALGORITHM: Held-Karp TSP with bitmask DP
//
// DP STATE:
//   dp[mask][i] = shortest distance to reach errand i,
//                 having visited exactly the errands in 'mask',
//                 starting from "work".
//
// MASK ENCODING:
//   Bit j set in mask ↔ errand j has been visited.
//   mask = 0b101 means errands 0 and 2 have been visited.
//
// RECURRENCE:
//   dp[1<<i][i] = dist(work, errand_i)   for all i    (base: first stop)
//   dp[mask | (1<<j)][j] = min(dp[mask][i] + dist(errand_i, errand_j))
//                           for all i in mask, j not in mask
//
// FINAL ANSWER:
//   best = min over all i: dp[FULL_MASK][i] + dist(errand_i, home)
//
// PATH RECONSTRUCTION:
//   parent[mask][i] = which errand came before i in the optimal path.
//   Walk backwards from (FULL_MASK, bestLast) to recover order.
//
// DIAGRAM (3 errands: A, B, C):
//   mask=001: dp[001][A] = dist(work, A)
//   mask=011: dp[011][B] = dp[001][A] + dist(A,B)
//             dp[011][A] = dp[010][B] + dist(B,A)
//   mask=111: try all last-visited errands + dist to home
//
// TIME: O(2^k * k^2)  where k = number of errands
// SPACE: O(2^k * k)
// Practical limit: k ≤ ~20
// =============================================================

#include <algorithm>
#include <bitset>
#include <cfloat>
#include <cmath>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

using namespace std;

struct Place {
  double x;
  double y;
};

// Euclidean distance between two places
double dist(const Place &a, const Place &b) {
  double dx = a.x - b.x;
  double dy = a.y - b.y;
  return sqrt(dx * dx + dy * dy);
}

int main() {
  int n;
  cin >> n; // number of named locations

  map<string, Place> placeMap;

  for (int i = 0; i < n; i++) {
    string name;
    cin >> name;
    Place p;
    cin >> p.x >> p.y;
    placeMap[name] = p;
  }

  string line;
  getline(cin, line); // consume trailing newline after location list

  vector<vector<string>> tasks; // each task = list of errand names

  while (getline(cin, line)) {
    if (line.empty())
      break;

    stringstream ss(line);
    string name;
    vector<string> t;
    while (ss >> name) {
      t.push_back(name);
    }
    tasks.push_back(t);
  }

  Place home = placeMap["home"];
  Place work = placeMap["work"];

  // Solve each task (each set of errands) independently
  for (auto &t : tasks) {
    int k = t.size(); // number of errands in this task
    if (k == 0)
      continue;

    vector<Place> errands(k);
    for (int i = 0; i < k; i++) {
      errands[i] = placeMap[t[i]];
    }

    // Precompute distances:
    //   d[i][j]   = distance between errands i and j
    //   d_work[i] = distance from work to errand i
    //   d_home[i] = distance from errand i back to home
    vector<vector<double>> d(k, vector<double>(k));
    vector<double> d_work(k), d_home(k);

    for (int i = 0; i < k; i++) {
      d_work[i] = dist(work, errands[i]);
      d_home[i] = dist(errands[i], home);
      for (int j = 0; j < k; j++) {
        d[i][j] = dist(errands[i], errands[j]);
      }
    }

    int FULL = 1 << k; // 2^k total masks
    // dp[mask][i] = shortest path from work visiting errands in 'mask', ending
    // at i
    vector<vector<double>> dp(FULL, vector<double>(k, DBL_MAX));
    // parent[mask][i] = previous errand index on the optimal path to (mask, i)
    vector<vector<int>> parent(FULL, vector<int>(k, -1));

    // Base case: single errand as the first stop
    for (int i = 0; i < k; i++) {
      dp[1 << i][i] = d_work[i]; // start from work, go to errand i
    }

    // Fill DP table: for each mask, try extending to an unvisited errand j
    for (int mask = 0; mask < FULL; mask++) {
      for (int i = 0; i < k; i++) {
        if (!(mask & (1 << i)))
          continue; // i not in mask → skip
        if (dp[mask][i] == DBL_MAX)
          continue; // unreachable → skip

        for (int j = 0; j < k; j++) {
          if (mask & (1 << j))
            continue; // j already visited → skip

          int newMask = mask | (1 << j); // add errand j to visited set
          double val = dp[mask][i] + d[i][j];

          if (val < dp[newMask][j]) {
            dp[newMask][j] = val;
            parent[newMask][j] = i; // came from errand i
          }
        }
      }
    }

    // Find the best final errand to visit before going home
    double best = DBL_MAX;
    int last = -1;
    int start = FULL - 1; // all errands visited

    for (int i = 0; i < k; i++) {
      double val = dp[start][i] + d_home[i]; // add distance home
      if (val < best) {
        best = val;
        last = i;
      }
    }

    // Reconstruct the path by following parent pointers backwards
    vector<int> path;
    int mask = start;

    while (last != -1) {
      path.push_back(last);
      int prev = parent[mask][last];
      mask ^= (1 << last); // remove 'last' from the mask (go backwards)
      last = prev;
    }

    reverse(path.begin(), path.end()); // path was built backwards

    // Output the errand names in the optimal visit order
    for (int i = 0; i < path.size(); i++) {
      if (i)
        cout << " ";
      cout << t[path[i]];
    }
    cout << "\n";
  }

  return 0;
}
