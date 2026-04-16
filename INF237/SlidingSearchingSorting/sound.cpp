// =============================================================
// SOUND — Sliding Window Maximum AND Minimum simultaneously
// =============================================================
//
// PROBLEM: Given n sound levels, a window size m, and a tolerance c,
//          find all 1-indexed window start positions where
//          max(window) - min(window) <= c  (the window is "acceptable").
//
// APPROACH: Run two monotonic deques in parallel:
//   - 'max' deque: monotonically DECREASING → front = window max
//   - 'min' deque: monotonically INCREASING → front = window min
//
// Both deques store INDICES. At each step, expire outdated fronts,
// maintain monotonic invariants at the back, then check the condition.
//
// TIME:  O(n)  — each element enters and leaves each deque at most once.
// SPACE: O(m)  — deques hold at most m indices each.
// =============================================================

#include <deque>
#include <iostream>
#include <vector>
using namespace std;

int main(void) {

  int n, m, c;
  cin >> n >> m >> c; // n elements, window size m, tolerance c

  vector<int> sounds(n);
  for (int i = 0; i < n; i++) {
    cin >> sounds[i];
  }

  deque<int> max; // indices, front = index of current window's MAXIMUM
  deque<int> min; // indices, front = index of current window's MINIMUM
  vector<int> res; // 1-indexed start positions of acceptable windows

  // ── PHASE 1: Process the first window [0 .. m-1] ──────────────────
  for (int i = 0; i < m; i++) {
    // Maintain max-deque: pop from back anything <= sounds[i]
    // (sounds[i] is larger and newer → they can never be max while i is in window)
    while (!max.empty() && sounds[max.back()] <= sounds[i]) {
      max.pop_back();
    }
    max.push_back(i);

    // Maintain min-deque: pop from back anything >= sounds[i]
    // (sounds[i] is smaller and newer → they can never be min while i is in window)
    while (!min.empty() && sounds[min.back()] >= sounds[i]) {
      min.pop_back();
    }
    min.push_back(i);
  }
  // Check the first window: start position = 1 (1-indexed)
  if (sounds[max.front()] - sounds[min.front()] <= c) {
    res.push_back(1);
  }

  // ── PHASE 2: Slide the window — i is the index of the NEW element ──
  // Window covers [i - m + 1 .. i]. Start position (1-indexed) = (i - m) + 2.
  for (int i = m; i < sounds.size(); i++) {
    // Expire front of max-deque if it's outside the new window
    while (!max.empty() && max.front() <= i - m) {
      max.pop_front();
    }
    // Maintain max-deque invariant at back
    while (!max.empty() && sounds[max.back()] <= sounds[i]) {
      max.pop_back();
    }
    max.push_back(i);

    // Expire front of min-deque if it's outside the new window
    while (!min.empty() && min.front() <= i - m) {
      min.pop_front();
    }
    // Maintain min-deque invariant at back
    while (!min.empty() && sounds[min.back()] >= sounds[i]) {
      min.pop_back();
    }
    min.push_back(i);

    // Check condition for the current window
    // sounds[max.front()] = current window max
    // sounds[min.front()] = current window min
    if (sounds[max.front()] - sounds[min.front()] <= c) {
      res.push_back((i - m) + 2); // convert to 1-indexed start position
    }
  }

  if (res.empty()) {
    cout << "NONE" << endl;
  } else {
    for (int i : res) {
      cout << i << endl;
    }
  }
}
