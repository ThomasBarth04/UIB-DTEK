// =============================================================
// 0/1 KNAPSACK — Classic Dynamic Programming
// =============================================================
//
// PROBLEM: Given n items each with a value and weight, and a
//          knapsack with capacity cap, pick items to maximise
//          total value without exceeding total weight.
//          Each item can be taken at most once (0/1 = take or leave).
//
// DP STATE:
//   dp[i][j] = max value using the first i items with capacity j
//
// RECURRENCE:
//   dp[i][j] = max(
//     dp[i-1][j],                         // don't take item i
//     val[i-1] + dp[i-1][j - wt[i-1]]    // take item i (only if wt[i-1] <= j)
//   )
//
// BASE CASE: dp[0][j] = 0  (no items → no value)
//            dp[i][0] = 0  (no capacity → no value)
//
// TABLE DIAGRAM (cap=5, items: val=[5,4,3,2], wt=[4,3,2,1]):
//
//       cap: 0  1  2  3  4  5
//   item 0:  0  0  0  0  0  0   ← base row (no items)
//   item 1:  0  0  0  0  5  5   ← can take item w=4,v=5 if cap>=4
//   item 2:  0  0  0  4  5  5   ← can take item w=3,v=4
//   item 3:  0  0  3  4  5  7   ← combining items gets 7 at cap=5
//   item 4:  0  2  3  5  6  7   ← best is still 7
//
// TRACEBACK: Walk backwards from dp[n][cap] to find which items were taken.
//   If dp[i][j] != dp[i-1][j] → item i was taken; subtract wt[i] from j.
//
// TIME:  O(n * cap)
// SPACE: O(n * cap)
// =============================================================

#include <algorithm>
#include <bits/stdc++.h>
#include <iostream>
#include <ostream>
#include <sched.h>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

void solveTest(int, vector<int>, vector<int>);

int main(int argc, char *argv[]) {
  vector<string> lines;
  string line;
  bool startOfTest = true;
  int counter = 0;
  int cap, n;
  vector<int> val;
  vector<int> wt;

  // Read input: first line of each test = "cap n", then n lines of "v w"
  while (std::getline(std::cin, line)) {
    stringstream ss(line);
    if (startOfTest) {
      ss >> cap >> n; // capacity and number of items
      startOfTest = false;
      counter = n;
    } else {
      if (counter > 0) {
        int v, w;
        ss >> v >> w;
        val.push_back(v); // value of item
        wt.push_back(w);  // weight of item
        counter--;
      }
      if (counter == 0) {
        startOfTest = true;
        solveTest(cap, val, wt);
        val.clear();
        wt.clear();
      }
    }
  }

  return 0;
}

void solveTest(int cap, vector<int> val, vector<int> wt) {
  int n = wt.size();

  // Build the (n+1) x (cap+1) DP table.
  // Row i corresponds to "using items 0..i-1".
  // Column j corresponds to "knapsack capacity j".
  vector<vector<int>> dp(n + 1, vector<int>(cap + 1));

  for (int i = 0; i <= n; i++) {
    for (int j = 0; j <= cap; j++) {
      if (i == 0 || j == 0) {
        dp[i][j] = 0; // base case: no items or no capacity → value 0
      } else {
        // Option 1: take item i (0-indexed: item i-1)
        // Only valid if the item fits in the remaining capacity
        int pick = 0;
        if (wt[i - 1] <= j) {
          // val[i-1]       = value gained from this item
          // dp[i-1][j - wt[i-1]] = best value with remaining capacity
          pick = val[i - 1] + dp[i - 1][j - wt[i - 1]];
        }

        // Option 2: skip item i — inherit the best value without it
        int noPick = dp[i - 1][j];

        dp[i][j] = max(pick, noPick); // take the better option
      }
    }
  }

  // ── TRACEBACK: Recover which items were actually taken ──────────────
  // Start at dp[n][cap] (bottom-right corner) and walk up.
  // If dp[y][x] != dp[y-1][x], item y was included — subtract its weight.
  int x_index = cap;        // current capacity (moves left as items are included)
  int y_index = val.size(); // current item row (moves up)

  vector<int> includedItems;
  for (int y_index = val.size(); y_index > 0; y_index--) {
    if (dp[y_index][x_index] != dp[y_index - 1][x_index]) {
      // Value changed → item y_index-1 (0-indexed) was taken
      includedItems.push_back(y_index - 1);
      x_index -= wt[y_index - 1]; // reduce remaining capacity
    }
    // If values are equal → item was skipped, just move up
  }

  cout << includedItems.size() << endl;

  for (int idx : includedItems) {
    cout << idx << " ";
  }
  cout << endl;
}
