// =============================================================
// MOVIE COLLECTION 2 — Segment Tree variant (0-indexed movies)
// =============================================================
//
// Same problem as moviecollection.cpp but with 0-indexed movies
// and a slightly different initialization approach.
//
// Key differences from moviecollection.cpp:
//   - Movies are 0-indexed (pos array has size m, not m+1)
//   - Initial segment tree filled directly (not via update() calls)
//   - movie input is decremented by 1 to convert to 0-indexed
//   - Otherwise identical algorithm
//
// See moviecollection.cpp for the full algorithm explanation and diagrams.
// =============================================================

#include <iostream>
#include <vector>

using namespace std;

int n;
vector<int> tree;

// Point update — set position pos to value, propagate sums up.
void update(int pos, int value) {
  pos += n;
  tree[pos] = value;

  while (pos > 1) {
    pos /= 2;
    tree[pos] = tree[2 * pos] + tree[2 * pos + 1];
  }
}

// Range sum [l, r] inclusive (0-based). See moviecollection.cpp for explanation.
int sum(int l, int r) {
  l += n;
  r += n;
  int result = 0;

  while (l <= r) {
    if (l % 2 == 1) result += tree[l++];
    if (r % 2 == 0) result += tree[r--];
    l /= 2;
    r /= 2;
  }
  return result;
}

int main() {
  int t;
  cin >> t;

  for (int i = 0; i < t; i++) {
    int m, r;
    cin >> m >> r;
    n = m + r; // r top slots + m original positions
    tree.assign(2 * n, 0);

    // 0-indexed: pos[i] = initial position of movie i
    vector<int> pos(m);
    for (int i = 0; i < m; i++) {
      pos[i] = i + r; // movies start at offset r
    }

    // Build the initial leaf layer directly (movies are at positions r..r+m-1 in the virtual array)
    // tree[leaf] = 1 means a movie is there
    for (int i = 0; i < m; i++) {
      tree[i + r + n] = 1; // leaf index = position + n  (using leaf offset)
    }
    // Build internal nodes bottom-up from the leaves we just set
    for (int i = n - 1; i > 0; i--) {
      tree[i] = tree[2 * i] + tree[2 * i + 1];
    }

    int top = r - 1; // next available top slot
    for (int i = 0; i < r; i++) {
      int movie;
      cin >> movie;
      movie--; // convert to 0-indexed

      int moviePos = pos[movie];

      // Count movies above this movie in the stack
      int result = sum(0, moviePos - 1);
      cout << result << " ";

      update(moviePos, 0);    // remove from current position
      update(top, 1);         // place at top slot
      pos[movie] = top;       // update recorded position

      top--; // decrement for next request
    }
    cout << endl;
  }

  return 0;
}
