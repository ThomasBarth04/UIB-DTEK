// =============================================================
// SLIDING WINDOW MAXIMUM — Deque-based O(n) algorithm
// =============================================================
//
// PROBLEM: Given an array and a window of size k, find the
//          maximum element in every window position.
//
// NAIVE: For each window, scan all k elements → O(n*k)
// SMART: Use a monotonic deque       → O(n)
//
// KEY IDEA — Monotonic Deque:
//   The deque stores INDICES (not values) of "candidate" maximums.
//   Invariant: deque is always in DECREASING order of values.
//              (front = largest, back = smallest)
//
//   When adding element i:
//     1. Remove from FRONT: indices that are out of the window (index <= i - k)
//     2. Remove from BACK:  indices whose values are <= arr[i]
//                           (they can never be the future max, i is larger AND newer)
//     3. Push i to back.
//     4. Front of deque = index of current window's maximum.
//
// DIAGRAM (windowSize=3, arr=[8,9,6,1,2,5,7,2,3,7]):
//
//   i=0: add 0(val=8)     deque=[0]         max=arr[0]=8
//   i=1: 9>8 → pop 0, add 1(9)  deque=[1]  max=arr[1]=9
//   i=2: 6<9 → add 2(6)  deque=[1,2]       window [8,9,6]: max=9
//   --- first window done ---
//   i=3: front=1, 1<=3-3=0 → expire.  3<6, add 3. deque=[2,3] max=arr[2]=6
//   i=4: front=2, 2<=4-3=1 → expire.  2>1, add 4. deque=[4]   max=arr[4]=2
//   ...
// =============================================================

#include <deque>
#include <iostream>
#include <vector>
using namespace std;

int main(int argc, char *argv[]) {

  vector<int> list = {8, 9, 6, 1, 2, 5, 7, 2, 3, 7};
  deque<int> max; // stores INDICES; invariant: list[max[0]] >= list[max[1]] >= ...
  int windowSize = 3;

  // ── PHASE 1: Fill the first window ──────────────────────────
  // No need to expire front (window hasn't slid yet).
  for (int i = 0; i < windowSize; i++) {
    // Maintain monotonic invariant: pop from back anything smaller than new element.
    // Reason: if list[back] <= list[i], list[back] can never be the max
    //         (i is both larger AND will leave the window later than back).
    while (!max.empty() && list[max.back()] <= list[i]) {
      max.pop_back();
    }
    max.push_back(i); // add current index as a candidate
  }
  cout << max.front() << endl; // print index of max in first window

  // ── PHASE 2: Slide the window (i = index of new element entering) ──
  for (int i = windowSize; i < list.size(); i++) {
    // Step 1: Expire the front if it's now outside the window.
    //         Window covers [i - windowSize + 1 .. i], so expire if front <= i - windowSize.
    while (!max.empty() && max.front() <= i - windowSize) {
      max.pop_front();
    }

    // Step 2: Maintain monotonic invariant — pop smaller back elements.
    while (!max.empty() && list[max.back()] < list[i]) {
      max.pop_back();
    }
    max.push_back(i); // new element enters as a candidate

    cout << max.front() << endl; // front is always the index of the current window's max
  }

  return 0;
}
