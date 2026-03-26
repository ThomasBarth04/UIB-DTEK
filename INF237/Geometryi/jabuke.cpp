#include <iostream>

using namespace std;

bool in_angle(pair<int, int> a, pair<int, int> b, pair<int, int> c,
              pair<int, int> d);
long long orient(pair<int, int> a, pair<int, int> b, pair<int, int> c);
int main(int argc, char *argv[]) {
  pair<int, int> a;
  pair<int, int> b;
  pair<int, int> c;
  cin >> a.first >> a.second;
  cin >> b.first >> b.second;
  cin >> c.first >> c.second;

  if (orient(a, b, c) < 0)
    swap(b, c);

  double area = abs(orient(a, b, c)) / 2.0;

  int N;
  cin >> N;

  int count = 0;

  for (int i = 0; i < N; ++i) {
    pair<int, int> P;
    cin >> P.first >> P.second;

    if (in_angle(a, b, c, P) && in_angle(c, a, b, P)) {
      count++;
    }
  }

  cout << fixed;
  cout.precision(1);
  cout << area << "\n";
  cout << count << "\n";

  return 0;
}
pair<int, int> subtract(pair<int, int> a, pair<int, int> b) {
  return {a.first - b.first, a.second - b.second};
}

long long cross(pair<int, int> a, pair<int, int> b) {
  return a.first * b.second - a.second * b.first;
}

long long orient(pair<int, int> a, pair<int, int> b, pair<int, int> c) {
  return cross(subtract(b, a), subtract(c, a));
}

bool in_angle(pair<int, int> a, pair<int, int> b, pair<int, int> c,
              pair<int, int> d) {
  return orient(a, b, d) >= 0 && orient(a, c, d) <= 0;
}
