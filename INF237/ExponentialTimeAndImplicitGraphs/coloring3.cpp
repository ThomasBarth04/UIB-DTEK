#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

struct Node {
  int id;
  vector<int> neighbors;
};

bool solve(int a, int k, vector<Node> &nodes);
int countAvailable(int v, int k, vector<Node> &nodes);
int n;
vector<int> node_colors;

int main() {
  cin.tie(nullptr);
  ios::sync_with_stdio(false);
  cin.exceptions(ios::failbit);
  cin >> n;
  cin.ignore();

  vector<Node> nodes(n);

  for (int i = 0; i < n; i++) {
    nodes[i].id = i;
  }

  for (int i = 0; i < n; i++) {
    string line;
    getline(cin, line);
    stringstream ss(line);
    int neighbor_index;

    while (ss >> neighbor_index) {
      nodes[i].neighbors.push_back(neighbor_index);
    }
  }

  // for (Node &node : nodes) {
  //   cout << "Node " << node.id << " neighbors:";
  //   for (Node *nbr : node.neighbors) {
  //     cout << " " << nbr->id;
  //   }
  //   cout << endl;
  // }

  for (int k = 1; k <= n; k++) {
    node_colors.assign(n, -1);

    if (solve(0, k, nodes)) {
      cout << k << endl;
      break;
    }
  }
  return 0;
}

bool solve(int a, int k, vector<Node> &nodes) {
  if (a == n) {
    return true;
  }

  int v = -1;
  int bestC = k + 1;
  for (int i = 0; i < nodes.size(); i++) {
    if (node_colors[i] != -1) {
      continue;
    }
    int c = countAvailable(i, k, nodes);
    if (c == 0)
      return false;
    if (c < bestC) {
      v = i;
      bestC = c;
    }
  }

  vector<bool> used(k + 1, false);
  for (int n : nodes[v].neighbors) {
    if (node_colors[n] != -1) {
      used[node_colors[n]] = true;
    }
  }

  for (int c = 1; c <= k; c++) {
    if (used[c]) {
      continue;
    }
    node_colors[v] = c;

    bool ok = true;
    for (int nb : nodes[v].neighbors) {
      if (node_colors[nb] == -1 && countAvailable(nb, k, nodes) == 0) {
        ok = false;
        break;
      }
    }
    if (ok) {
      if (solve(a + 1, k, nodes)) {
        return true;
      }
    }
    node_colors[v] = -1;
  }
  return false;
}

int countAvailable(int v, int k, vector<Node> &nodes) {
  vector<bool> used(k + 1, false);
  for (int n : nodes[v].neighbors) {
    if (node_colors[n] != -1)
      used[node_colors[n]] = true;
  }
  int count = 0;
  for (int c = 1; c <= k; c++)
    if (!used[c])
      count++;
  return count;
}
