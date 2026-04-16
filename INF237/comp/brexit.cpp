// =============================================================
// BREXIT — Cascade Elimination via Stack
// =============================================================
//
// PROBLEM: c countries are partners. Each country i starts with some
//          partners. Country l starts the "leave" cascade.
//          A country LEAVES if, after losing a partner, it has ≤ half of
//          its ORIGINAL partner count remaining.
//
//          If country x (the query target) ends up leaving → print "leave".
//          If x remains → print "stay".
//
// ALGORITHM: Iterative cascade using a stack.
//
//   1. Push l (the initial leaving country) onto the stack.
//   2. Pop a country from the stack. For each of its current partners:
//      a. Remove the leaving country from the partner's list.
//      b. If partner's remaining count <= original_count / 2 → they leave too.
//         Push them on the stack.
//      c. If the target x is pushed → print "leave" immediately and exit.
//   3. If x was never pushed → print "stay".
//
// WHY STACK? This is DFS-order cascade. BFS (queue) would also work for
//   correctness, since we just need to propagate the cascade to completion.
//
// PARTNER COUNT TRACKING:
//   partners[c] = list of current partners of country c (mutable — we erase from it)
//   start_partners[c] = original partner count of c (fixed — used to compute threshold)
//
// DIAGRAM:
//   l leaves. For each of l's partners p:
//     p loses 1 partner. If p.remaining <= p.original/2 → p leaves too.
//     Cascade ripples outward.
//
// SPECIAL CASE: If l == x initially → print "leave" immediately.
//
// TIME: O(p)  where p = total number of partnerships (each edge removed at most once)
// =============================================================

#include <execution>
#include <iomanip>
#include <iostream>
#include <map>
#include <stack>
#include <vector>
using namespace std;

int main(int argc, char *argv[]) {
  cin.tie(nullptr);
  ios::sync_with_stdio(false);
  cin.exceptions(ios::failbit);
  cout << setprecision(4) << fixed;

  int c, p, x, l;
  cin >> c >> p >> x >> l;
  x--; // convert to 0-indexed
  l--;

  // start_partners[i] = original number of partners of country i
  map<int, int> start_partners;
  // partners[i] = current list of partners (modified during cascade)
  vector<vector<int>> partners(c, vector<int>());

  for (int i = 0; i < p; i++) {
    int c1, c2;
    cin >> c1 >> c2;
    c1--;
    c2--;
    start_partners[c1] += 1;
    start_partners[c2] += 1;

    partners[c1].push_back(c2);
    partners[c2].push_back(c1);
  }

  stack<int> stack;
  stack.push(l); // l starts the cascade

  // Edge case: query country is the same as the initial leaver
  if (l == x) {
    cout << "leave" << endl;
    return 0;
  }

  // Process the cascade: each leaving country may trigger its partners to leave
  while (!stack.empty()) {
    int curr = stack.top();
    stack.pop();

    // Notify all of curr's current partners that curr is leaving
    for (int c : partners[curr]) {
      // Remove curr from c's partner list
      partners[c].erase(find(partners[c].begin(), partners[c].end(), curr));

      // Check if c now has <= half its original partners → c must leave too
      if (partners[c].size() <= start_partners[c] / 2) {
        stack.push(c);
        if (c == x) {
          // Target country x is leaving
          cout << "leave" << endl;
          return 0;
        }
      }
    }
    // Clear curr's own partner list (curr has already left, no longer relevant)
  }

  // Cascade finished and x was never triggered → x stays
  cout << "stay" << endl;

  return 0;
}
