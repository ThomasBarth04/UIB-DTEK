#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <vector>

using namespace std;

struct person {
  string name;
  int id;
  double speed;
  string reportsTo;
  string tostring() { return name + " " + to_string(speed) + " " + reportsTo; }
};

unordered_map<string, int> nameToIndex;
int main() {
  int n;
  cin >> n;
  vector<person> people(n);
  vector<vector<int>> subs(n, vector<int>());

  for (int i = 0; i < n; i++) {
    person p;
    cin >> p.name >> p.speed >> p.reportsTo;
    p.id = i;
    people[i] = p;
    nameToIndex[p.name] = i;
  }

  int root = -1;
  for (auto &p : people) {
    if (p.reportsTo == "CEO") {
      root = p.id;
    } else {
      subs[nameToIndex[p.reportsTo]].push_back(p.id);
    }
  }

  vector<int> stack;
  vector<int> tree;
  stack.push_back(root);

  vector<pair<int, double>> alone(n, {0, 0});
  vector<pair<int, double>> onTeam(n, {0, 0});

  while (!stack.empty()) {
    int current = stack.back();
    stack.pop_back();
    tree.push_back(current);
    for (int sub : subs[current]) {
      stack.push_back(sub);
    }
  }

  for (int i = tree.size() - 1; i >= 0; i--) {
    int currentTeam = 0;
    double currentSpeed = 0;

    for (int p : subs[tree[i]]) {
      currentTeam += alone[p].first;
      currentSpeed += alone[p].second;
    }

    onTeam[tree[i]] = {currentTeam, currentSpeed};
    pair<int, double> best = {currentTeam, currentSpeed};

    for (int p : subs[tree[i]]) {
      int candT = currentTeam - alone[p].first + onTeam[p].first + 1;
      double candS = currentSpeed - alone[p].second + onTeam[p].second +
                     min(people[p].speed, people[tree[i]].speed);

      if (candT > best.first || (candT == best.first && candS > best.second)) {
        best = {candT, candS};
      }
    }
    alone[tree[i]] = best;
  }

  cout << alone[root].first << " " << (alone[root].second / alone[root].first)
       << endl;
  return 0;
}
