// =============================================================
// SCRATCH / TEST FILE
// =============================================================
// This is a scratch file used to test the tomography / Gale-Ryser
// satisfiability check with a hardcoded example.
// Not part of the main solution — see tomography.cpp for the full solution.
// =============================================================

#include <bits/stdc++.h>
using namespace std;

// Function to check if matrix exists (Gale-Ryser necessary conditions only)
bool matrix_exist(int row[], int column[], int r, int c) {
  int row_sum = 0;
  int column_sum = 0;
  int row_max = -1;
  int column_max = -1;
  int row_non_zero = 0;
  int column_non_zero = 0;

  // Compute row stats: total sum, max, count of non-zero rows
  for (int i = 0; i < r; i++) {
    row_sum += row[i];
    row_max = max(row_max, row[i]);
    if (row[i])
      row_non_zero++;
  }

  // Compute column stats
  for (int i = 0; i < c; i++) {
    column_sum += column[i];
    column_max = max(column_max, column[i]);
    if (column[i])
      column_non_zero++;
  }

  // Necessary conditions (not sufficient — use satisfiable() for the full check):
  // 1. Total row sums must equal total column sums
  // 2. Largest row sum ≤ number of non-zero column sums
  // 3. Largest column sum ≤ number of non-zero row sums
  if ((row_sum != column_sum) || (row_max > column_non_zero) ||
      (column_max > row_non_zero))
    return false;

  return true;
}

// FULL Gale-Ryser greedy check
// Source - https://stackoverflow.com/a/21004546
// Posted by MvG, modified by community. See post 'Timeline' for change history
// Retrieved 2026-04-06, License - CC BY-SA 3.0
bool satisfiable(std::vector<int> a, std::vector<int> b) {
  while (!a.empty()) {
    std::sort(b.begin(), b.end(), std::greater<int>());
    int k = a.back();
    a.pop_back();
    if (k > b.size())
      return false;
    if (k == 0)
      continue;
    if (b[k - 1] == 0)
      return false;
    for (int i = 0; i < k; i++)
      b[i]--;
  }
  for (std::vector<int>::iterator i = b.begin(); i != b.end(); i++)
    if (*i != 0)
      return false;
  return true;
}

// Driver Code
int main() {
  vector<int> row = {3, 3, 1, 1};
  vector<int> column = {4, 3, 1};

  if (satisfiable(row, column))
    cout << "Yes";
  else
    cout << "No";
  return 0;
}
