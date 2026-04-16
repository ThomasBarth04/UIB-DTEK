#include <algorithm>
#include <iostream>
#include <vector>
using namespace std;

double cross(pair<int, int> a, pair<int, int> b, pair<int, int> c) {
  return (double)(b.first - a.first) * (c.second - a.second) -
         (double)(b.second - a.second) * (c.first - a.first);
}

vector<pair<int, int>> convexHull(vector<pair<int, int>> &points) {
  int n = points.size(), k = 0;
  sort(points.begin(), points.end());
  vector<pair<int, int>> hull(2 * n);
  for (int i = 0; i < n; i++) {
    while (k >= 2 && cross(hull[k - 2], hull[k - 1], points[i]) <= 0)
      k--;
    hull[k++] = points[i];
  }
  for (int i = n - 2, t = k + 1; i >= 0; i--) {
    while (k >= t && cross(hull[k - 2], hull[k - 1], points[i]) <= 0)
      k--;
    hull[k++] = points[i];
  }
  hull.resize(k - 1);
  return hull;
}

bool insideConvexHull(const vector<pair<int, int>> &ch, pair<int, int> p) {
  int n = ch.size();
  if (n < 3) {
    return false;
  }
  if (cross(ch[0], p, ch[1]) > 1e-9) {
    return false;
  }

  if (cross(ch[0], p, ch[n - 1]) < -1e-9) {
    return false;
  }

  int lo = 2, hi = n - 1, seg = -1;
  while (lo <= hi) {
    int mid = (lo + hi) / 2;
    if (cross(ch[0], p, ch[mid]) > -1e-9) {
      seg = mid;
      hi = mid - 1;
    } else
      lo = mid + 1;
  }
  if (seg == -1) {
    return false;
  }

  return cross(ch[seg - 1], p, ch[seg]) < 1e-9;
}

int main() {
  ios::sync_with_stdio(false);
  cin.tie(nullptr);
  int n;
  while (cin >> n) {
    vector<pair<int, int>> points(n);
    for (int i = 0; i < n; i++) {
      cin >> points[i].first >> points[i].second;
    }

    vector<pair<int, int>> ch = convexHull(points);
    int m;
    cin >> m;
    int count = 0;
    for (int i = 0; i < m; i++) {
      pair<int, int> p;
      cin >> p.first >> p.second;
      if (insideConvexHull(ch, p)) {
        count++;
      }
    }
    cout << count << "\n";
  }
  return 0;
}
