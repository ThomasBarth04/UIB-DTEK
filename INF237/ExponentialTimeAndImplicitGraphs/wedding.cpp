// =============================================================
// WEDDING SEATING — 2-SAT (Two-Satisfiability)
// =============================================================
//
// PROBLEM: n married couples must be seated so that:
//   1. Each husband (ih) and wife (iw) sit on OPPOSITE sides.
//   2. The bride cannot see both members of any affair.
//      (An affair is a pair (a, b) where a and b should NOT both be
//       on the SAME side — i.e., at least one must be on the other side.)
//
// ENCODING AS 2-SAT:
//   Each person x is a boolean variable:
//     var(x) = 2x   → x is on side TRUE (e.g. left)
//     neg(x) = 2x+1 → x is on side FALSE (right)
//
//   Constraint 1: For each couple (h, w): h ≠ w
//     (h=T → w=F) AND (h=F → w=T) AND (w=T → h=F) AND (w=F → h=T)
//     Encoded as 4 implications.
//
//   Constraint 2: For each affair pair (a, b): NOT (a=F AND b=F)
//     i.e., ¬a → b  AND  ¬b → a
//     (if a is on the false side, b must be on the true side, and vice versa)
//
// 2-SAT ALGORITHM (Kosaraju's SCC):
//
//   1. Build implication graph: edge (x → y) means "if x is true, y must be true"
//   2. Find all SCCs using Kosaraju's two-DFS algorithm:
//      a. DFS on original graph → record finish order
//      b. DFS on REVERSED graph in reverse finish order → assigns SCC numbers
//   3. Check satisfiability: for each variable x,
//      if x and ¬x are in the same SCC → UNSATISFIABLE.
//   4. Extract assignment: x = true if comp[var(x)] > comp[neg(x)]
//      (SCCs with higher number in Kosaraju = earlier in topological order of condensation)
//
// DIAGRAM (Kosaraju's algorithm):
//
//   Pass 1 (DFS on G):        Pass 2 (DFS on G^R in rev finish order):
//   Record finish order        Assign SCC IDs
//   node finished last → first in pass 2 → gets SCC 0 (source)
//
// TIME: O(V + E) for Kosaraju
// =============================================================

#include <iostream>
#include <string>
#include <vector>

using namespace std;

int n, m;

vector<vector<int>> graph, reverseG;
vector<int> order, comp;
vector<bool> visited;

// var(x) = positive literal index for person x (2*x = TRUE side)
int var(int x) { return 2 * x; }
// neg(x) = negated literal (2*x XOR 1 = 2*x+1 = FALSE side)
int neg(int x) { return x ^ 1; }

// Add implication edge a → b to both graphs (for Kosaraju)
void add_edge(int a, int b) {
  graph[a].push_back(b);
  reverseG[b].push_back(a); // reverse graph needed for Kosaraju pass 2
}

// DFS pass 1: explore original graph, record finish order
void dfs1(int v) {
  visited[v] = true;
  for (int to : graph[v])
    if (!visited[to])
      dfs1(to);
  order.push_back(v); // finished: add to order (later = higher priority for pass 2)
}

// DFS pass 2: explore reversed graph, assign SCC component IDs
void dfs2(int v, int c) {
  comp[v] = c; // assign this SCC number
  for (int to : reverseG[v])
    if (comp[to] == -1) // unvisited in reversed graph
      dfs2(to, c);
}

// Convert person string (e.g. "3h" or "2w") to variable index
int personToIndex(string s) {
  int x = stoi(s.substr(0, s.size() - 1)); // numeric part
  char t = s.back();                        // 'h' or 'w'
  return 2 * x + (t == 'h');               // h → odd index, w → even index
}

int main() {
  while (cin >> n >> m) {
    int total_people = 2 * n;      // n husbands + n wives
    int totale_nodes = total_people * 2; // each person has 2 literals (T and F)

    graph.assign(2 * total_people, {});
    reverseG.assign(totale_nodes, {});

    // CONSTRAINT 1: Each couple sits on opposite sides
    // h=TRUE → w=FALSE,  h=FALSE → w=TRUE  (and vice versa)
    for (int i = 0; i < n; i++) {
      int h = personToIndex(to_string(i) + "h");
      int w = personToIndex(to_string(i) + "w");

      add_edge(var(h), neg(var(w))); // if h is TRUE → w must be FALSE
      add_edge(var(w), neg(var(h))); // if w is TRUE → h must be FALSE
      add_edge(neg(var(h)), var(w)); // if h is FALSE → w must be TRUE
      add_edge(neg(var(w)), var(h)); // if w is FALSE → h must be TRUE
    }

    // CONSTRAINT 2: For each affair pair (a, b), not BOTH on false side
    // ¬a → b  AND  ¬b → a
    for (int i = 0; i < m; i++) {
      string a, b;
      cin >> a >> b;

      int x = personToIndex(a);
      int y = personToIndex(b);

      add_edge(neg(var(x)), var(y)); // if x is FALSE → y must be TRUE
      add_edge(neg(var(y)), var(x)); // if y is FALSE → x must be TRUE
    }

    // ── Kosaraju's SCC Algorithm ─────────────────────────────────────
    // Pass 1: DFS on original graph, fill finish order
    visited.assign(totale_nodes, false);
    order.clear();
    for (int i = 0; i < totale_nodes; i++)
      if (!visited[i])
        dfs1(i);

    // Pass 2: DFS on reversed graph in reverse finish order → assign SCCs
    comp.assign(totale_nodes, -1);
    int j = 0;
    for (int i = totale_nodes - 1; i >= 0; i--) {
      int v = order[i]; // process in reverse finish order
      if (comp[v] == -1)
        dfs2(v, j++);
    }

    // ── Check satisfiability and extract assignment ───────────────────
    vector<int> assignment(total_people);
    bool ok = true;

    for (int i = 0; i < total_people; i++) {
      if (comp[2 * i] == comp[2 * i + 1]) {
        // Variable x and ¬x are in the same SCC → contradiction → unsatisfiable
        ok = false;
        break;
      }
      // x is TRUE if its positive literal SCC comes LATER in Kosaraju numbering
      // (higher comp number = later processed = source in condensation DAG)
      assignment[i] = comp[2 * i] > comp[2 * i + 1];
    }

    if (!ok) {
      cout << "bad luck\n";
      continue;
    }

    // Output all people on the TRUE side (skip couple 0 = the bride and groom)
    for (int i = 0; i < n; i++) {
      int h = personToIndex(to_string(i) + "h");
      int w = personToIndex(to_string(i) + "w");

      if (i == 0) continue; // skip the bride and groom themselves

      if (assignment[h]) cout << i << "h ";
      if (assignment[w]) cout << i << "w ";
    }

    cout << "\n";
  }

  return 0;
}
