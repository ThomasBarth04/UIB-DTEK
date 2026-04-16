// =============================================================
// JUST FOR SIDEKICKS — Segment Tree with Per-Gem-Type Counts
// =============================================================
//
// PROBLEM: A sequence of n positions, each holding one of 6 gem types.
//          Support 3 operations:
//   1. Update: change gem at position k to type p.
//   2. Update: change the VALUE of gem type p to v.
//   3. Query:  sum of values of all gems in range [l, r].
//
// DATA STRUCTURE:
//   Each node in the segment tree stores an array of 6 counters:
//     tree[node][g] = how many gems of type g are in this node's range.
//
//   Range sum = Σ (gemValue[g] * countInRange[g]) for g in 0..5
//
//   This separates "gem positions" from "gem values", so updating a
//   gem's value (op 2) only needs to change gemValue[] — no tree rebuild.
//
// SEGMENT TREE STRUCTURE (flat array, 1-indexed, size 2n):
//   - Leaves: tree[n .. 2n-1],  tree[i+n][s[i]-'1'] = 1 for the initial gem
//   - Internal nodes: tree[i][g] = tree[2i][g] + tree[2i+1][g]
//
// DIAGRAM (n=4, positions 0-3):
//            [1] root
//          /       \
//       [2]         [3]
//      /   \       /   \
//    [4]  [5]   [6]  [7]  ← leaves (indices 4..7 = n..2n-1)
//    pos0 pos1  pos2 pos3
//
// OPERATIONS:
//   update(pos, newGem): clear leaf, set new gem counter, bubble up.
//   sum(l, r):           walk tree with two-pointer, accumulate per-gem counts.
//
// TIME: O(log n) per update/query, O(n) to build.
// =============================================================

#include <array>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

int n;                      // number of positions (size of leaf layer)
vector<array<int, 6>> tree; // segment tree: each node has 6 gem-type counters
vector<long long> gemValue(6); // current value of each gem type (indexed 0..5)

void update(int pos, int newGem);
long long sum(int l, int r);

int main() {
  int q;
  cin >> n >> q; // n positions, q operations

  // Read initial gem values for the 6 types
  for (int i = 0; i < 6; i++)
    cin >> gemValue[i];

  string s;
  cin >> s; // initial gem assignment, s[i] in '1'..'6'

  tree.resize(2 * n); // leaves at [n .. 2n-1], internal nodes at [1 .. n-1]

  // Initialize leaves: each leaf gets a 1 in the slot for its gem type
  for (int i = 0; i < n; i++) {
    tree[i + n].fill(0);
    tree[i + n][s[i] - '1'] += 1; // convert '1'..'6' to index 0..5
  }

  // Build internal nodes bottom-up: parent = sum of two children for each gem
  // type
  for (int i = n - 1; i > 0; i--) {
    for (int g = 0; g < 6; g++) {
      tree[i][g] = (tree[2 * i][g] + tree[2 * i + 1][g]);
    }
  }

  for (int i = 0; i < q; i++) {
    int a;
    cin >> a;

    if (a == 1) {
      // Operation 1: change gem at position k (1-indexed) to type p (1-indexed)
      int k, p;
      cin >> k >> p;
      k--; // convert to 0-indexed position
      p--; // convert to 0-indexed gem type
      update(k, p);
    } else if (a == 2) {
      // Operation 2: set value of gem type p (1-indexed) to v
      int p;
      long long v;
      cin >> p >> v;
      p--;
      gemValue[p] = v; // just update the value array — no tree rebuild needed
    } else {
      // Operation 3: query value sum in range [l, r] (1-indexed, inclusive)
      int l, r;
      cin >> l >> r;
      l--; // convert to 0-indexed
      r--;
      cout << sum(l, r) << "\n";
    }
  }
}

// Update position pos (0-indexed) to hold gem type newGem (0-indexed).
// Clear the leaf, set the new gem, then walk up to root recomputing sums.
void update(int pos, int newGem) {
  pos += n;              // shift to leaf layer
  tree[pos].fill(0);     // clear all 6 gem counters at this leaf
  tree[pos][newGem] = 1; // mark the new gem type

  // Propagate up: each ancestor = sum of its two children
  while (pos > 1) {
    pos /= 2;
    for (int i = 0; i < 6; i++) {
      tree[pos][i] = tree[2 * pos][i] + tree[2 * pos + 1][i];
    }
  }
}

// Sum of gem values in range [l, r] (0-indexed, inclusive).
// Uses the two-pointer technique: walk from leaves up, collecting
// nodes that are entirely inside the range.
long long sum(int l, int r) {
  l += n; // shift to leaf layer
  r += n;

  long long total = 0;

  while (l <= r) {
    if (l % 2 == 1) {
      // l is a right child → add it directly, then move l right
      for (int g = 0; g < 6; g++) {
        total += gemValue[g] * tree[l][g]; // value × count for each gem type
      }
      l++;
    }
    if (r % 2 == 0) {
      // r is a left child → add it directly, then move r left
      for (int g = 0; g < 6; g++) {
        total += gemValue[g] * tree[r][g];
      }
      r--;
    }
    l /= 2; // move both pointers up one level
    r /= 2;
  }

  return total;
}
