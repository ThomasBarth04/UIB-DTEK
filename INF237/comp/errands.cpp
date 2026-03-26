#include <bits/stdc++.h>
using namespace std;

struct Point {
  double x;
  double y;
};

static double dist(const Point &a, const Point &b) {
  double dx = a.x - b.x;
  double dy = a.y - b.y;
  return sqrt(dx * dx + dy * dy);
}

int main() {
  ios::sync_with_stdio(false);
  cin.tie(nullptr);

  int n;
  if (!(cin >> n)) {
    return 0;
  }

  unordered_map<string, int> id;
  vector<string> names(n);
  vector<Point> points(n);

  for (int i = 0; i < n; ++i) {
    cin >> names[i] >> points[i].x >> points[i].y;
    id[names[i]] = i;
  }

  const int work = id["work"];
  const int home = id["home"];

  string line;
  getline(cin, line);

  constexpr double INF = 1e100;
  while (getline(cin, line)) {
    if (line.empty()) {
      continue;
    }

    istringstream iss(line);
    vector<string> stops;
    string stop;
    while (iss >> stop) {
      stops.push_back(stop);
    }

    int m = (int)stops.size();
    vector<int> stopIds(m);
    for (int i = 0; i < m; ++i) {
      stopIds[i] = id[stops[i]];
    }

    vector<double> fromWork(m), toHome(m);
    vector<vector<double>> between(m, vector<double>(m, 0.0));
    for (int i = 0; i < m; ++i) {
      fromWork[i] = dist(points[work], points[stopIds[i]]);
      toHome[i] = dist(points[stopIds[i]], points[home]);
      for (int j = 0; j < m; ++j) {
        between[i][j] = dist(points[stopIds[i]], points[stopIds[j]]);
      }
    }

    int fullMask = 1 << m;
    vector<vector<double>> dp(fullMask, vector<double>(m, INF));
    vector<vector<int>> parent(fullMask, vector<int>(m, -1));

    for (int i = 0; i < m; ++i) {
      dp[1 << i][i] = fromWork[i];
    }

    for (int mask = 1; mask < fullMask; ++mask) {
      for (int last = 0; last < m; ++last) {
        if (!(mask & (1 << last))) {
          continue;
        }
        if (dp[mask][last] >= INF / 2) {
          continue;
        }

        for (int nxt = 0; nxt < m; ++nxt) {
          if (mask & (1 << nxt)) {
            continue;
          }
          int nextMask = mask | (1 << nxt);
          double cand = dp[mask][last] + between[last][nxt];
          if (cand < dp[nextMask][nxt]) {
            dp[nextMask][nxt] = cand;
            parent[nextMask][nxt] = last;
          }
        }
      }
    }

    int bestLast = 0;
    double bestCost = INF;
    int doneMask = fullMask - 1;
    for (int last = 0; last < m; ++last) {
      double total = dp[doneMask][last] + toHome[last];
      if (total < bestCost) {
        bestCost = total;
        bestLast = last;
      }
    }

    vector<int> order;
    int mask = doneMask;
    int cur = bestLast;
    while (cur != -1) {
      order.push_back(cur);
      int prev = parent[mask][cur];
      mask ^= 1 << cur;
      cur = prev;
    }
    reverse(order.begin(), order.end());

    for (int i = 0; i < m; ++i) {
      if (i) {
        cout << ' ';
      }
      cout << stops[order[i]];
    }
    cout << '\n';
  }

  return 0;
}
