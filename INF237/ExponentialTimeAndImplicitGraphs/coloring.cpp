#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

struct Node {
  int id;
  vector<int> neighbors;
};

bool solve(int a, int k, vector<int> &node_colors, vector<Node> &nodes,
           vector<int> &available_count);
int n;

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

  int startK = 1;
  for (int i = 0; i < n; i++)
    startK = max(startK, (int)nodes[i].neighbors.size());

  // for (Node &node : nodes) {
  //   cout << "Node " << node.id << " neighbors:";
  //   for (Node *nbr : node.neighbors) {
  //     cout << " " << nbr->id;
  //   }
  //   cout << endl;
  // }

  for (int k = startK; k <= n; k++) {
    vector<int> color(n, -1);
    vector<int> available_count(n, k);
    if (solve(0, k, color, nodes, available_count)) {
      cout << k << endl;
      break;
    }
  }
  return 0;
}

bool validColor(int v, int c, vector<int> &node_colors, vector<Node> &nodes) {
  for (int nb : nodes[v].neighbors)
    if (node_colors[nb] == c)
      return false;
  return true;
}

bool solve(int a, int k, vector<int> &node_colors, vector<Node> &nodes,
           vector<int> &available_count) {
  if (a == (int)nodes.size())
    return true;

  int v = -1;
  int bestC = k + 1;
  for (int i = 0; i < n; i++) {
    if (node_colors[i] != -1)
      continue;
    if (available_count[i] == 0)
      return false;
    if (available_count[i] < bestC ||
        (available_count[i] == bestC && v != -1 &&
         nodes[i].neighbors.size() > nodes[v].neighbors.size())) {
      v = i;
      bestC = available_count[i];
    }
  }

  int nReduced[n];
  int nReducedSize = 0;

  for (int c = 1; c <= k; c++) {
    if (!validColor(v, c, node_colors, nodes))
      continue;

    nReducedSize = 0;
    bool possible = true;

    for (int nb : nodes[v].neighbors) {
      if (node_colors[nb] != -1)
        continue;
      if (validColor(nb, c, node_colors, nodes)) {
        available_count[nb]--;
        nReduced[nReducedSize++] = nb;
        if (available_count[nb] == 0) {
          possible = false;
          break;
        }
      }
    }

    if (possible) {
      node_colors[v] = c;
      if (solve(a + 1, k, node_colors, nodes, available_count))
        return true;
      node_colors[v] = -1;
    }

    for (int i = 0; i < nReducedSize; i++)
      available_count[nReduced[i]]++;
  }
  return false;
}
