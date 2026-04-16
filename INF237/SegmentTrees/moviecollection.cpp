// =============================================================
// MOVIE COLLECTION — Segment Tree for "Movies Before Current"
// =============================================================
//
// PROBLEM: You have m movies in a stack (initially ordered 1..m).
//          For each request (a movie), count how many movies are
//          ABOVE it in the stack, then move it to the TOP.
//
// KEY TRICK — Map to a larger array using extra "top slots":
//   Use an array of size m + r (where r = number of requests).
//   Initially, movie i sits at position r + i - 1 (1-indexed).
//   The first r positions [0..r-1] are reserved as "top slots" for moved movies.
//   Each time a movie is requested, move it to the next available top slot.
//
//   Position array:
//   [0 ... r-1] [r ... r+m-1]
//    (reserved)  (initial positions)
//       ↑
//   currentTop starts at r-1, decrements each request.
//
// SEGMENT TREE (point update, range sum):
//   tree[pos] = 1 if a movie is at that position, 0 otherwise.
//   "How many movies are above" = sum of positions [0 .. moviePos - 1].
//
// EXAMPLE (m=3 movies, r=3 requests):
//   Initial positions: movie1@3, movie2@4, movie3@5
//   Request movie2:
//     - sum(0..3) = 0 movies above → output 0
//     - Remove movie2 from pos 4, place at top slot 2
//   Request movie3:
//     - movie3 is at pos 5; sum(0..4) = 1 movie above (movie2) → output 1
//   ...
//
// TIME per query: O(log(m+r)) for both update and range sum
// =============================================================

#include <iostream>
#include <vector>

using namespace std;

int n;          // total segment tree size (m + r)
vector<int> tree; // flat segment tree array, size 2*n

// Point update: set position 'pos' to 'value', propagate up to root.
// This is the "bottom-up" segment tree style where leaves are at [n .. 2n-1].
void update(int pos, int value) {
  pos += n;       // shift to leaf layer
  tree[pos] = value;

  // Walk up to root, recomputing each parent as sum of its two children
  while (pos > 1) {
    pos /= 2;
    tree[pos] = tree[2 * pos] + tree[2 * pos + 1];
  }
}

// Range sum query [l, r] (0-based, inclusive).
// The iterative "two-pointer" segment tree technique:
//
//   Start l and r at the leaf layer. Walk up:
//   - If l is a RIGHT child (l % 2 == 1): include tree[l], move l right.
//   - If r is a LEFT child  (r % 2 == 0): include tree[r], move r left.
//   Then move both up one level.
//
//   Intuition: when l is a right child, its sibling is outside [l,r]
//              so we must add l's value directly before moving up.
//              Same logic for r being a left child.
int sum(int l, int r) {
  l += n; // shift to leaf layer
  r += n;
  int result = 0;

  while (l <= r) {
    if (l % 2 == 1) result += tree[l++]; // l is right child: take it, move right
    if (r % 2 == 0) result += tree[r--]; // r is left child:  take it, move left
    l /= 2; // move up
    r /= 2;
  }
  return result;
}

int main() {

  int t;
  cin >> t; // number of test cases

  for (int i = 0; i < t; i++) {
    int m, r;
    cin >> m >> r; // m movies, r requests

    // Total virtual array size: r "top slots" + m original slots
    n = m + r;
    tree.assign(2 * n, 0);

    // pos[movie] = current position of movie (1-indexed movies, so pos has size m+1)
    vector<int> pos(m + 1);

    // Initially movie i sits at position r + i - 1 (0-indexed virtual array)
    for (int i = 1; i <= m; i++) {
      pos[i] = r + i - 1;
      update(pos[i], 1); // mark this position as occupied
    }

    int currentTop = r - 1; // next available "top slot" (starts at r-1, goes down)

    for (int i = 0; i < r; i++) {
      int movie;
      cin >> movie;

      int moviePos = pos[movie];

      // Count movies above (in positions [0 .. moviePos - 1])
      int result = sum(0, moviePos - 1);
      cout << result << " ";

      // Remove movie from its current position
      update(moviePos, 0);

      // Place movie at the top
      pos[movie] = currentTop;
      update(currentTop, 1);

      currentTop--; // next request gets the slot one below this one
    }

    cout << "\n";
  }

  return 0;
}
