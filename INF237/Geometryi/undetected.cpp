#include <iostream>
#include <vector>

using namespace std;

struct DSU {
  vector<int> parent;
  vector<int> rank;

  DSU(int n) {
    parent.resize(n);
    rank.resize(n);
    for (int i = 0; i < n; i++) {
      parent[i] = i;
      rank[i] = 0; // dybde på tre
    }
  }
  int find(int x) {
    if (parent[x] != x) {
      parent[x] = find(parent[x]);
    }
    return parent[x];
  }

  void unionSet(int x, int y) {
    x = find(x);
    y = find(y);
    if (x == y) { // samme root
      return;
    }
    // tar minstre root i dybde og fester på største
    if (rank[x] < rank[y]) {
      parent[x] = y;
    } else if (rank[x] > rank[y]) {
      parent[y] = x;
    } else {
      parent[y] = x;
      rank[x]++;
    }
  }
};

struct sensor {
  double x;
  double y;
  double radius;
};

int main() {

  int N;
  cin >> N;

  vector<sensor> s(N);

  for (int i = 0; i < N; i++)
    cin >> s[i].x >> s[i].y >> s[i].radius;

  int LEFT = N;
  int RIGHT = N + 1;
  DSU dsu(N + 2);

  // ide, legg til k sensorer helt til L og R er i samme gruppe, da returner
  // k-1

  for (int k = 0; k < N; k++) {
    for (int j = 0; j < k; j++) {
      long long dx = s[k].x - s[j].x;
      long long dy = s[k].y - s[j].y;
      long long dist = dx * dx + dy * dy;
      long long rr =
          (long long)(s[k].radius + s[j].radius) * (s[k].radius + s[j].radius);

      if (dist <= rr)
        dsu.unionSet(k, j);
    }

    if (s[k].x - s[k].radius <= 0)
      dsu.unionSet(k, LEFT);

    if (s[k].x + s[k].radius >= 200)
      dsu.unionSet(k, RIGHT);

    if (dsu.find(LEFT) == dsu.find(RIGHT)) {
      cout << k << "\n";
      return 0;
    }
  }

  cout << N << "\n";
}
