#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

struct Node {
  int id;
  int neighbors;
};

int main() {
  int n;
  cin >> n;

  vector<Node> nodes(n);
  for (int i = 0; i < n; i++) {
    nodes[i].id = i;
  }

  string line;
  getline(cin, line);

  for (int i = 0; i < n; i++) {
    getline(cin, line);
    istringstream ss(line);
    int nb;
    while (ss >> nb) {
      nodes[i].neighbors |= (1 << nb);
      nodes[nb].neighbors |= (1 << i);
    }
  }

  // for (Node &node : nodes) {
  //   cout << "Node " << node.id << " neighbors: " << node.neighbors << endl;
  // }

  int total = 1 << n;

  vector<bool> is_independent(total, true);
  for (int mask = 1; mask < total; mask++) {
    for (int v = 0; v < n; v++) {
      if (!((mask >> v) & 1))
        continue;
      if (nodes[v].neighbors & mask) {
        is_independent[mask] = false;
        break;
      }
    }
  }

  vector<int> dp(total, n + 1);
  dp[0] = 0;

  for (int mask = 1; mask < total; mask++) {
    for (int sub = mask; sub > 0; sub = (sub - 1) & mask) {
      if (!is_independent[sub])
        continue;
      if (dp[mask ^ sub] + 1 < dp[mask])
        dp[mask] = dp[mask ^ sub] + 1;
    }
  }

  cout << dp[total - 1] << endl;
  return 0;
}
