// =============================================================
// COMPANY PICNIC — Tree DP: Maximum Pairs with Best Average Speed
// =============================================================
//
// PROBLEM: A rooted company tree where each node has a name and speed.
//          Form pairs (boss, direct report). A pair scores min(speed[boss],
//          speed[report]). Maximise number of pairs. Break ties by maximising
//          average min-speed.
//
// DP STATES (per node v):
//   alone[v]  = best (numPairs, sumMinSpeeds) from v's subtree when v is FREE
//               (v's parent may still choose to pair with v)
//   onTeam[v] = best (numPairs, sumMinSpeeds) from v's subtree when v is TAKEN
//               (v is already paired with its parent, so v cannot pair with any
//               child)
//
// KEY INSIGHT — the swap trick:
//   For alone[v], start from onTeam[v] as a baseline (pair with nobody).
//   To try pairing v with child c, swap c's contribution:
//     candidate = baseline - alone[c] + onTeam[c] + 1 + min(spd[v], spd[c])
//   This avoids re-summing all children for each candidate — O(children) per
//   node.
//
// RECURRENCE:
//   onTeam[v] = sum of alone[c]  for all children c   (v is taken, children are
//   free) alone[v]  = max over {
//                 onTeam[v],                            (don't pair v with
//                 anyone) onTeam[v] - alone[c] + onTeam[c]
//                           + 1 + min(spd[v], spd[c])  (pair v with child c)
//               }  for each child c
//
// TRAVERSAL: Iterative post-order (leaves before parents).
//   Push root onto stack → collect pre-order in tree[] → iterate tree[] in
//   reverse.
//
// COMPARISON: pairs first (more pairs wins), then sumMinSpeeds (higher sum
// wins).
//
// FINAL ANSWER: alone[root].numPairs, alone[root].sumSpeeds / numPairs
//
// TIME: O(n)   SPACE: O(n)
// =============================================================

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
  vector<vector<int>> subs(
      n, vector<int>()); // subs[v] = children of v in the company tree

  // ── Read input ────────────────────────────────────────────────────────────
  for (int i = 0; i < n; i++) {
    person p;
    cin >> p.name >> p.speed >> p.reportsTo;
    p.id = i;
    people[i] = p;
    nameToIndex[p.name] = i;
  }

  // ── Build tree (root = person who reports directly to "CEO") ──────────────
  int root = -1;
  for (auto &p : people) {
    if (p.reportsTo == "CEO") {
      root = p.id; // CEO's direct report is the tree root
    } else {
      subs[nameToIndex[p.reportsTo]].push_back(p.id);
    }
  }

  // ── Iterative post-order traversal ────────────────────────────────────────
  // Push root → collect nodes in pre-order (parent before children) in tree[].
  // Iterating tree[] in reverse gives post-order (children before parents),
  // which guarantees children's DP tables are ready before their parent's.
  vector<int> stack;
  vector<int> tree;
  stack.push_back(root);
  while (!stack.empty()) {
    int current = stack.back();
    stack.pop_back();
    tree.push_back(current);
    for (int sub : subs[current])
      stack.push_back(sub);
  }

  // ── DP tables ─────────────────────────────────────────────────────────────
  // alone[v]  = (numPairs, sumMinSpeeds) for v's subtree when v is free
  // onTeam[v] = (numPairs, sumMinSpeeds) for v's subtree when v is taken by
  // parent
  vector<pair<int, double>> alone(n, {0, 0});
  vector<pair<int, double>> onTeam(n, {0, 0});

  // ── Fill DP bottom-up (post-order) ────────────────────────────────────────
  for (int i = tree.size() - 1; i >= 0; i--) {
    int v = tree[i];

    // onTeam[v]: v is taken, so every child contributes its best alone result.
    int currentTeam = 0;
    double currentSpeed = 0;
    for (int c : subs[v]) {
      currentTeam += alone[c].first;
      currentSpeed += alone[c].second;
    }
    onTeam[v] = {currentTeam, currentSpeed};

    // alone[v]: v is free. Start with the "pair nobody" baseline (= onTeam[v]).
    // Then try pairing v with each child c via the swap trick:
    //   swap c's contribution from alone[c] → onTeam[c], add the new pair.
    pair<int, double> best = {currentTeam, currentSpeed}; // baseline: no pair
    for (int c : subs[v]) {
      int candT = currentTeam - alone[c].first + onTeam[c].first + 1;
      double candS = currentSpeed - alone[c].second + onTeam[c].second +
                     min(people[c].speed, people[v].speed);
      // Prefer more pairs; break ties by higher total min-speed sum.
      if (candT > best.first || (candT == best.first && candS > best.second))
        best = {candT, candS};
    }
    alone[v] = best;
  }

  // ── Output ────────────────────────────────────────────────────────────────
  // alone[root] holds the global optimum. Average = sumSpeeds / numPairs.
  cout << alone[root].first << " " << (alone[root].second / alone[root].first)
       << endl;

  return 0;
}
