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

  while (std::getline(std::cin, line)) {
    stringstream ss(line);
    if (startOfTest) {
      ss >> cap >> n;
      startOfTest = false;
      counter = n;
    } else {
      if (counter > 0) {
        int v, w;
        ss >> v >> w;
        val.push_back(v);
        wt.push_back(w);
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

  // vector<int> val = {5, 4, 3, 2};
  // vector<int> wt = {4, 3, 2, 1};
  // solveTest(cap, val, wt);
  return 0;
}

void solveTest(int cap, vector<int> val, vector<int> wt) {
  int n = wt.size();
  vector<vector<int>> dp(n + 1, vector<int>(cap + 1));

  for (int i = 0; i <= n; i++) {
    for (int j = 0; j <= cap; j++) {
      if (i == 0 || j == 0) {
        dp[i][j] = 0;
      } else {
        int pick = 0;

        if (wt[i - 1] <= j) {
          pick = val[i - 1] + dp[i - 1][j - wt[i - 1]];
        }

        int noPick = dp[i - 1][j];

        dp[i][j] = max(pick, noPick);
      }
    }
  }

  // for (int i = 0; i <= n; i++) {
  //   for (int j = 0; j <= cap; j++) {
  //     cout << dp[i][j] << " ";
  //   }
  //   cout << endl;
  // }

  int x_index = cap;        // left right
  int y_index = val.size(); // up down

  int itemcount = 0;
  vector<int> includedItems;
  for (int y_index = val.size(); y_index > 0; y_index--) {
    if (dp[y_index][x_index] != dp[y_index - 1][x_index]) {
      includedItems.push_back(y_index - 1);
      x_index -= wt[y_index - 1];
    }
  }

  //
  // for (int y_index = val.size(); y_index > 0; y_index--) {
  //   if (dp[y_index][x_index] != dp[y_index - 1][x_index]) {
  //     itemcount++;
  //
  //     int current_sum = dp[y_index][x_index];
  //     int item_val = val[y_index];
  //     int diff = current_sum - item_val;
  //
  //     includedItems.push_back(y_index);
  //
  //     while (x_index > 0) {
  //       if (dp[y_index - 1][x_index] == diff) {
  //         break;
  //       }
  //       x_index--;
  //     }
  //   }
  // }
  // cout << itemcount << endl;
  // for (int i : includedItems) {
  //   cout << i << " ";
  // }
  cout << includedItems.size() << endl;

  for (int idx : includedItems) {
    cout << idx << " ";
  }
  cout << endl;
}
