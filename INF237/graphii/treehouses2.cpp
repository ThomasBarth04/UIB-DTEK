#include <cmath>
#include <iostream>
#include <vector>

// 1 create W graph
// 2 mst

using namespace std;

struct Node {
  double x;
  double y;
  int id;
};

// hypot(x2 - x1, y2 - y1);
int main(int argc, char *argv[]) {
  int n, e, p;
  cin >> n >> e >> p;
  vector<Node> nodes(n);
  vector<vector<bool>> zeroEdges(n, vector<bool>(n, false));

  for (int i = 0; i < n; i++) {
    Node node;
    cin >> node.x >> node.y;
    node.id = i;
    nodes[i] = node;
  }

  for (int i = 0; i < e; i++) {
    for (int j = i + 1; j < e; j++) {
      Node a = nodes[i];
      Node b = nodes[j];
      zeroEdges[i][j] = true;
      zeroEdges[j][i] = true;
    }
  }
  for (int i = 0; i < p; i++) {
    int a, b;
    cin >> a >> b;
    a--;
    b--;
    zeroEdges[a][b] = true;
  }

  vector<bool> inmst(n, false);
  vector<double> dists(n, INFINITY);
  dists[0] = 0;

  double sum = 0;
  for (int i = 0; i < n; i++) {
    int pick = -1;
    for (int j = 0; j < n; j++) {
      if (!inmst[j] && (pick == -1 || dists[j] < dists[pick])) {
        pick = j;
      }
    }
    sum += dists[pick];
    inmst[pick] = true;

    for (int g = 0; g < n; g++) {
      if (inmst[g]) {
        continue;
      }
      double dist;
      if (zeroEdges[pick][g]) {
        dist = 0;
      } else {
        dist = hypot(nodes[pick].x - nodes[g].x, nodes[pick].y - nodes[g].y);
      }

      if (dist < dists[g]) {
        dists[g] = dist;
      }
    }
  }
  cout << sum << endl;

  return 0;
}
