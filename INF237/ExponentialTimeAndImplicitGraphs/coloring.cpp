#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

struct Node {
  int id;
  vector<Node *> neighbors;
};

int n;

int main() {
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
      nodes[i].neighbors.push_back(&nodes[neighbor_index]);
    }
  }

  // for (Node &node : nodes) {
  //   cout << "Node " << node.id << " neighbors:";
  //   for (Node *nbr : node.neighbors) {
  //     cout << " " << nbr->id;
  //   }
  //   cout << endl;
  // }

  vector<int> node_colors(n, -1);
  int max_color = 1;

  for (int i = 0; i < n; i++) {
    Node node = nodes[i];
    vector<int> n_colors;
    for (Node *nbr : node.neighbors) {
      if (node_colors[nbr->id] != -1) {
        n_colors.push_back(node_colors[nbr->id]);
      }
    }
    int current_color = 1;
    while (find(n_colors.begin(), n_colors.end(), current_color) !=
           n_colors.end()) {
      current_color++;
    }
    node_colors[i] = current_color;
    if (current_color > max_color) {
      max_color = current_color;
    }
  }
  cout << max_color << endl;
  return 0;
}
