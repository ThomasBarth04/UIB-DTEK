// =============================================================
// WATCH YOUR STEP 2 — Grid Path Counting with Obstacles (DP)
// =============================================================
//
// PROBLEM: Count the number of paths from corner (a,b) to corner (c,d)
//          on a grid, moving only RIGHT or DOWN, while avoiding two
//          "mine" positions (e,f) and (g,h).
//
// INPUT: a b c d e f g h  (two corners of the grid, two mines)
//
// APPROACH: Dynamic Programming on a 2D grid.
//
//   dp[x][y] = number of paths from the top-left (0,0) to cell (x,y)
//              without passing through either mine.
//
// RECURRENCE:
//   dp[0][0] = 1                     (starting cell: one way to be here)
//   dp[x][y] = 0                     if (x,y) is a mine
//   dp[x][y] = dp[x-1][y] + dp[x][y-1]   otherwise (came from left OR above)
//
// COORDINATE TRANSFORM:
//   The input gives absolute grid corners; we normalize by subtracting
//   the top-left corner (a,b) so our grid is 0-indexed from (0,0).
//   Mine positions become relative: m1x = e-a, m1y = f-b, etc.
//
// DIAGRAM (small example, mine at (1,1)):
//
//   (0,0) → (1,0) → (2,0)
//     ↓              ↓
//   (0,1)   [mine]  (2,1)
//     ↓              ↓
//   (0,2) → (1,2) → (2,2)
//
//   dp values:
//   1  1  1
//   1  0  1
//   1  1  2    → answer = 2 paths to (2,2)
//
// TIME:  O(width * height)
// SPACE: O(width * height)
// =============================================================

#include <iostream>
#include <vector>
using namespace std;

int main(int argc, char *argv[]) {
  int a, b, c, d, e, f, g, h;
  cin >> a >> b >> c >> d >> e >> f >> g >> h;
  // (a,b) = top-left corner, (c,d) = bottom-right corner
  // (e,f) = mine 1,          (g,h) = mine 2

  // Normalize: shift so the grid starts at (0,0)
  int width  = c - a + 1; // number of columns
  int height = d - b + 1; // number of rows

  // Mine positions in normalized coordinates
  int m1x = e - a, m1y = f - b;
  int m2x = g - a, m2y = h - b;

  // dp[x][y] = number of paths from (0,0) to (x,y)
  vector<vector<long long>> map(width, vector<long long>(height, 0));
  map[0][0] = 1; // exactly one way to stand at the start

  for (int x = 0; x < width; x++) {
    for (int y = 0; y < height; y++) {
      if (x == 0 && y == 0) {
        continue; // already initialized to 1
      }
      if ((x == m1x && y == m1y) || (x == m2x && y == m2y)) {
        map[x][y] = 0; // mine cell: no valid paths pass through here
        continue;
      }

      // Add paths arriving from the left (if not on leftmost column)
      if (x > 0) {
        map[x][y] += map[x - 1][y];
      }
      // Add paths arriving from above (if not on top row)
      if (y > 0) {
        map[x][y] += map[x][y - 1];
      }
    }
  }

  // Answer is the number of paths reaching the bottom-right corner
  cout << map[width - 1][height - 1] << endl;
  return 0;
}
