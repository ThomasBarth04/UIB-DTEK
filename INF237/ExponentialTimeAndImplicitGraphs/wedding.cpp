#include <iostream>
#include <string>
#include <vector>

using namespace std;

// 1. husband og wife ikke på samme side
// 2. bride kan ikke se folk på samme side som seg selv
// 3. bride kan ikke se begge medlem av utroskap

// så split hvert ektepar og bride ikke se begge medlem av utroskap
//
//  2x = true
//  2x + 1 = false

int n, m;

vector<vector<int>> graph, reverseG;
vector<int> order, comp;
vector<bool> visited;

int var(int x) { return 2 * x; }
int neg(int x) { return x ^ 1; }

void add_edge(int a, int b) {
  graph[a].push_back(b);
  reverseG[b].push_back(a);
}

void dfs1(int v) {
  visited[v] = true;
  for (int to : graph[v])
    if (!visited[to])
      dfs1(to);
  order.push_back(v);
}

void dfs2(int v, int c) {
  comp[v] = c;
  for (int to : reverseG[v])
    if (comp[to] == -1)
      dfs2(to, c);
}

int personToIndex(string s) {
  int x = stoi(s.substr(0, s.size() - 1));
  char t = s.back();
  return 2 * x + (t == 'h');
}

int main() {
  while (cin >> n >> m) {
    int total_people = 2 * n;

    // hver person kan enten være true eller false
    int totale_nodes = total_people * 2;

    graph.assign(2 * total_people, {});
    reverseG.assign(totale_nodes, {});

    for (int i = 0; i < n; i++) {
      int h = personToIndex(to_string(i) + "h");
      int w = personToIndex(to_string(i) + "w");

      add_edge(var(h), neg(var(w)));
      add_edge(var(w), neg(var(h)));

      add_edge(neg(var(h)), var(w));
      add_edge(neg(var(w)), var(h));
    }

    for (int i = 0; i < m; i++) {
      // ulovelig a = false og b = false
      string a, b;
      cin >> a >> b;

      int x = personToIndex(a);
      int y = personToIndex(b);

      add_edge(neg(var(x)), var(y));
      add_edge(neg(var(y)), var(x));
    }

    visited.assign(totale_nodes, false);
    order.clear();

    for (int i = 0; i < totale_nodes; i++)
      if (!visited[i])
        dfs1(i);

    comp.assign(totale_nodes, -1);
    int j = 0;

    for (int i = totale_nodes - 1; i >= 0; i--) {
      int v = order[i];
      if (comp[v] == -1)
        dfs2(v, j++);
    }

    vector<int> assignment(total_people);

    bool ok = true;
    for (int i = 0; i < total_people; i++) {
      if (comp[2 * i] == comp[2 * i + 1]) {
        ok = false;
        break;
      }
      assignment[i] = comp[2 * i] > comp[2 * i + 1];
    }

    if (!ok) {
      cout << "bad luck\n";
      continue;
    }

    for (int i = 0; i < n; i++) {
      int h = personToIndex(to_string(i) + "h");
      int w = personToIndex(to_string(i) + "w");

      if (i == 0)
        continue;

      if (assignment[h])
        cout << i << "h ";
      if (assignment[w])
        cout << i << "w ";
    }

    cout << "\n";
  }

  return 0;
}
