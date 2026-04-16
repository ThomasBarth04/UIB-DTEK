// =============================================================
// TOMOGRAPHY — Does a 0/1 Matrix Exist? (Gale-Ryser Theorem)
// =============================================================
//
// PROBLEM: Given row sums and column sums, determine if a 0/1 matrix
//          (binary matrix) exists with those sums.
//
// THEOREM (Gale-Ryser):
//   A 0/1 matrix with row sums R = [r1, ..., rm] and
//   column sums C = [c1, ..., cn] (sorted descending) EXISTS if and only if:
//
//   For all k = 1..n:
//     Σ(i=1..k) c_i  ≤  Σ(j=1..m) min(r_j, k)
//
//   Equivalently (necessary conditions before checking Gale-Ryser):
//     1. Sum of row sums == Sum of column sums  (total 1s must agree)
//     2. Max row sum ≤ Number of non-zero column sums  (can distribute across columns)
//     3. Max col sum ≤ Number of non-zero row sums     (can distribute across rows)
//
// ALGORITHM (satisfiable function, attributed to MvG on StackOverflow):
//   1. Sort column sums descending.
//   2. For each row sum r_i (process rows one at a time):
//      - Take r_i units, distributed to the TOP r_i columns (greedily).
//      - Decrement the top r_i column sums by 1.
//      - Re-sort columns after each row (keeps largest first).
//   3. If at any point we can't fill a row (not enough non-zero columns), return false.
//   4. After all rows: check all column sums are 0.
//
// NOTE: The matrix_exist() function checks only necessary conditions (not sufficient).
//       The satisfiable() function applies the full Gale-Ryser greedy check.
//
// EXAMPLE:
//   row sums = [3,3,1,1], col sums = [4,3,1]
//   Total row: 8, total col: 8 ✓
//   The satisfiable() greedy:
//     Row r=3: sort cols=[4,3,1], decrement top 3 → cols=[3,2,0] ✓
//     Row r=3: sort cols=[3,2,0], decrement top 3 → cols=[2,1,-1] ✗ → False? Actually...
//   → "Yes" if satisfiable returns true, "No" otherwise.
// =============================================================

#include <bits/stdc++.h>
using namespace std;

// NECESSARY CONDITIONS ONLY — not complete (commented out in main)
bool matrix_exist(int row[], int column[], int r, int c) {
  int row_sum = 0, column_sum = 0;
  int row_max = -1, column_max = -1;
  int row_non_zero = 0, column_non_zero = 0;

  for (int i = 0; i < r; i++) {
    row_sum += row[i];
    row_max = max(row_max, row[i]);
    if (row[i]) row_non_zero++;
  }

  for (int i = 0; i < c; i++) {
    column_sum += column[i];
    column_max = max(column_max, column[i]);
    if (column[i]) column_non_zero++;
  }

  // Condition 1: total 1s in rows must equal total 1s in columns
  // Condition 2: largest row sum can't exceed the number of usable columns
  // Condition 3: largest col sum can't exceed the number of usable rows
  if ((row_sum != column_sum) || (row_max > column_non_zero) ||
      (column_max > row_non_zero))
    return false;

  return true;
}

// FULL GALE-RYSER CHECK (greedy algorithm)
// Source: https://stackoverflow.com/a/21004546
// Posted by MvG, modified by community. See post 'Timeline' for change history
// Retrieved 2026-04-06, License - CC BY-SA 3.0
bool satisfiable(std::vector<int> a, std::vector<int> b) {
  while (!a.empty()) {
    // Sort column sums descending (Gale-Ryser requires this at each step)
    std::sort(b.begin(), b.end(), std::greater<int>());

    int k = a.back(); // take one row sum
    a.pop_back();

    // This row has k ones; we must place them in the k largest columns
    if (k > b.size()) return false; // not enough columns to place k ones

    if (k == 0) continue; // row of all zeros → no placement needed

    // The k-th largest column sum must be > 0 to accept another 1
    if (b[k - 1] == 0) return false; // not enough non-zero columns

    // Distribute the k ones to the top k columns (greedy: largest first)
    for (int i = 0; i < k; i++)
      b[i]--;
  }

  // After processing all rows, all column sums must be exactly 0
  for (std::vector<int>::iterator i = b.begin(); i != b.end(); i++)
    if (*i != 0) return false;

  return true;
}

int main() {
  // Test case: rows=[3,3,1,1], cols=[4,3,1]
  vector<int> row = {3, 3, 1, 1};
  vector<int> column = {4, 3, 1};

  if (satisfiable(row, column))
    cout << "Yes";
  else
    cout << "No";
  return 0;
}
