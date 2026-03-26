#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

struct Node {
  int id;
  vector<int> neighbors;
};

void solve(int a, int k, vector<int> &node_colors, vector<Node> &nodes);

int n;
int best;

int main() {
  cin >> n;
  vector<Node> nodes(n);
  for (int i = 0; i < n; i++)
    nodes[i].id = i;

  string line;
  getline(cin, line);
  for (int i = 0; i < n; i++) {
    getline(cin, line);
    istringstream ss(line);
    int nb;
    while (ss >> nb)
      nodes[i].neighbors.push_back(nb);
  }

  // for (Node &node : nodes) {
  //   cout << "Node " << node.id << " neighbors:";
  //   for (int nbr : node.neighbors) {
  //     cout << " " << nbr;
  //   }
  //   cout << endl;
  // }

  vector<int> node_colors(n, -1);
  best = 0;
  for (int i = 0; i < n; i++) {
    vector<bool> used(n, false);
    for (int nb : nodes[i].neighbors)
      if (node_colors[nb] != -1)
        used[node_colors[nb]] = true;
    for (int c = 0; c < n; c++)
      if (!used[c]) {
        node_colors[i] = c;
        break;
      }
    best = max(best, node_colors[i] + 1);
  }

  node_colors.assign(n, -1);
  solve(0, 0, node_colors, nodes);

  cout << best << endl;
  return 0;
}

int saturation(int v, vector<int> &node_colors, vector<Node> &nodes) {
  vector<bool> seen(best, false);
  int sat = 0;
  for (int nb : nodes[v].neighbors)
    if (node_colors[nb] != -1 && !seen[node_colors[nb]]) {
      seen[node_colors[nb]] = true;
      sat++;
    }
  return sat;
}

bool validColor(int v, int c, vector<int> &node_colors, vector<Node> &nodes) {
  for (int nb : nodes[v].neighbors)
    if (node_colors[nb] == c)
      return false;
  return true;
}

void solve(int a, int k, vector<int> &node_colors, vector<Node> &nodes) {
  if (a == n) {
    best = min(best, k);
    return;
  }

  int v = -1;
  int bestSat = -1;
  int bestDeg = -1;

  for (int i = 0; i < n; i++) {
    if (node_colors[i] != -1) {
      continue;
    }

    int sat = saturation(i, node_colors, nodes);
    int deg = (int)nodes[i].neighbors.size();
    if (sat > bestSat || (sat == bestSat && deg > bestDeg)) {
      v = i;
      bestSat = sat;
      bestDeg = deg;
    }
  }

  int maxC = min(k, best - 1);
  for (int c = 0; c <= maxC; c++) {
    if (!validColor(v, c, node_colors, nodes))
      continue;
    node_colors[v] = c;
    solve(a + 1, max(k, c + 1), node_colors, nodes);
    node_colors[v] = -1;
  }
}
