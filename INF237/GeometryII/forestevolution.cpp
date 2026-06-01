#include <algorithm>
#include <iostream>
#include <vector>
#include <iomanip> 

using namespace std;

double cross(pair<double, double> a, pair<double, double> b,
             pair<double, double> c);

pair<double, double> intersect(pair<double, double> a, pair<double, double> b,
                               pair<double, double> c, pair<double, double> d);
double area(vector<pair<double, double>> &poly);
vector<pair<double, double>> convexHull(vector<pair<double, double>> &points);
vector<pair<double, double>> cp(vector<pair<double, double>> &poly,
                                pair<double, double> a, pair<double, double> b);

int main() {
  cout << fixed << setprecision(15);

  int p, a;
  cin >> p >> a;

  vector<pair<double, double>> pine(p);
  for (int i = 0; i < p; i++) {
    cin >> pine[i].first >> pine[i].second;
  }

  vector<pair<double, double>> aspens(a);
  for (int i = 0; i < a; i++) {
    cin >> aspens[i].first >> aspens[i].second;
  }

  vector<pair<double, double>> hp = convexHull(pine);
  vector<pair<double, double>> ha = convexHull(aspens);

  if (hp.size() < 3 || ha.size() < 3) {
    cout << "0\n";
    return 0;
  }

  vector<pair<double, double>> inter = hp;
  int m = ha.size();

  for (int i = 0; i < m && !inter.empty(); i++) {
    inter = cp(inter, ha[i], ha[(i + 1) % m]);
  }
  if (inter.size() < 3) {
    cout << 0.0 << "\n";
    return 0;
  }

  cout << area(inter) << "\n";
  return 0;
}

double cross(pair<double, double> a, pair<double, double> b,
             pair<double, double> c) {
  return (b.first - a.first) * (c.second - a.second) -
         (b.second - a.second) * (c.first - a.first);
}

pair<double, double> intersect(pair<double, double> a, pair<double, double> b,
                               pair<double, double> c, pair<double, double> d) {
  double A1 = b.second - a.second;
  double B1 = a.first - b.first;
  double C1 = A1 * a.first + B1 * a.second;

  double A2 = d.second - c.second;
  double B2 = c.first - d.first;
  double C2 = A2 * c.first + B2 * c.second;

  double det = A1 * B2 - A2 * B1;
  if (abs(det) < 1e-12) return a;
  double x = (B2 * C1 - B1 * C2) / det;
  double y = (C2 * A1 - C1 * A2) / det;
  return {x, y};
}

vector<pair<double, double>> cp(vector<pair<double, double>> &poly,
                                pair<double, double> a,
                                pair<double, double> b) {
  vector<pair<double, double>> res;
  int n = poly.size();
  for (int i = 0; i < n; i++) {
    pair<double, double> s = poly[i];
    pair<double, double> t = poly[(i + 1) % n];
    double cs = cross(a, b, s);
    double ct = cross(a, b, t);
    if (cs >= 0){
      res.push_back(s);
    }

    if ((cs >= 0) != (ct >= 0))
      res.push_back(intersect(a, b, s, t));
  }
  return res;
}

vector<pair<double, double>> convexHull(vector<pair<double, double>> &points) {
  int n = points.size(), k = 0;
  if (n < 2) return points;
  sort(points.begin(), points.end());
  vector<pair<double, double>> hull(2 * n);
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

double area(vector<pair<double, double>> &poly) {
  int n = poly.size();
  if (n < 3) return 0.0;
  double res = 0;
  for (int i = 0; i < n; i++) {
    int j = (i + 1) % n;
    res += poly[i].first * poly[j].second;
    res -= poly[j].first * poly[i].second;
  }
  return abs(res) / 2.0;
}
