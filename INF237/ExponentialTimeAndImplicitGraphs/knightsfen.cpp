// =============================================================
// KNIGHT'S FEN — IDA* (Iterative Deepening A*) on an Implicit Graph
// =============================================================
//
// PROBLEM: A 5×5 board has knights ('0' and '1') and one empty space (' ').
//          Using knight moves to slide pieces into the blank, transform
//          the board into the goal state in ≤ 10 moves.
//
// GOAL STATE:
//   11111
//   01111
//   00 11
//   00001
//   00000
//
// ALGORITHM: IDA* (Iterative Deepening A-star)
//   - Like DFS but with a depth limit (iterative deepening from 0 to 10).
//   - PRUNING with an admissible heuristic:
//     h(state) = number of cells that differ from goal / 2
//     (each wrong cell requires at least one move, but each move can fix ≤ 2 cells)
//   - If current_depth + h(state) > maxMoves → prune this branch.
//
// IDA* DIAGRAM:
//   max=0: try all boards with 0 moves → if goal found, done
//   max=1: try all boards with 1 move (using pruning to skip hopeless paths)
//   ...
//   max=10: try up to 10 moves with pruning
//
// KNIGHT MOVES (from the blank position, swap with a knight):
//   (-2,-1), (-2,+1), (-1,-2), (-1,+2),
//   (+1,-2), (+1,+2), (+2,-1), (+2,+1)
//
// The blank cell is treated as the "moving piece" — we swap it with
// a valid knight at a knight-move distance.
//
// TIME: O(8^k) in the worst case (8 moves per step, k depth limit),
//       but pruning via heuristic makes it much faster in practice.
// =============================================================

#include <iostream>
#include <vector>

using namespace std;

bool solveTest(vector<string> lines, int n, int max);
bool checkIfDone(vector<string> &lines);
int diffFromGoal(const vector<string> &lines);
vector<pair<int, int>> getPossibleMoves(vector<string> &lines,
                                        pair<int, int> blank);

// Target board state to reach
vector<string> goal = {"11111", "01111", "00 11", "00001", "00000"};

int main() {
  int n;
  cin >> n;
  cin.ignore(); // consume the newline after n
  for (int i = 0; i < n; i++) {
    vector<string> l(5);

    for (int j = 0; j < 5; j++) {
      getline(cin, l[j]); // read each row of the 5×5 board
    }

    // Try increasing depth limits (IDA* outer loop)
    bool found = false;
    for (int maxMoves = 0; maxMoves <= 10; maxMoves++) {
      if (solveTest(l, 0, maxMoves)) {
        found = true;
        break;
      }
    }
    if (!found) {
      cout << "Unsolvable in less than 11 move(s)." << endl;
    }
  }

  return 0;
}

// Recursive DFS with depth limit and heuristic pruning.
// lines = current board state
// n     = current depth (moves made so far)
// max   = maximum allowed depth for this IDA* iteration
bool solveTest(vector<string> lines, int n, int max) {
  // Depth exceeded the current limit → prune
  if (n > max) return false;

  // Hard cap (should be unreachable given the outer loop limit of 10)
  if (n > 10) return false;

  // HEURISTIC PRUNING: if remaining moves can't possibly reach the goal → prune
  int diff = diffFromGoal(lines);
  if (diff + n > max) return false;

  // Base case: goal reached!
  if (checkIfDone(lines)) {
    cout << "Solvable in " << n << " move(s)." << endl;
    return true;
  }

  // Find the blank cell position
  int empty_r = -1, empty_c = -1;
  for (int r = 0; r < 5; r++) {
    for (int c = 0; c < 5; c++) {
      if (lines[r][c] == ' ') {
        empty_r = r;
        empty_c = c;
      }
    }
  }

  // Get all valid knight-move destinations from the blank
  vector<pair<int, int>> moves = getPossibleMoves(lines, {empty_r, empty_c});

  for (pair<int, int> move : moves) {
    // Swap blank with the knight at 'move' position
    swap(lines[empty_r][empty_c], lines[move.first][move.second]);

    // Recurse with one more move used
    if (solveTest(lines, n + 1, max)) {
      return true;
    };

    // Undo the move (backtrack)
    swap(lines[empty_r][empty_c], lines[move.first][move.second]);
  }

  return false;
}

// Returns all valid knight-move destinations FROM the blank cell.
// A destination is valid if it's inside the 5×5 board AND contains a piece ('0' or '1').
vector<pair<int, int>> getPossibleMoves(vector<string> &lines,
                                        pair<int, int> blank) {
  // All 8 possible knight move offsets
  vector<pair<int, int>> kMoves = {{-2, -1}, {-2, 1}, {-1, -2}, {-1, 2},
                                   {1, -2},  {1, 2},  {2, -1},  {2, 1}};

  vector<pair<int, int>> legalMoves;
  int blank_r = blank.first;
  int blank_c = blank.second;
  for (int i = 0; i < 8; i++) {
    int r = blank_r + kMoves[i].first;
    int c = blank_c + kMoves[i].second;

    // Check board bounds
    if (r < 0 || r > 4 || c < 0 || c > 4) continue;

    // Only swap with actual pieces ('0' or '1'), not another blank
    if (lines[r][c] == '0' || lines[r][c] == '1') {
      legalMoves.push_back({r, c});
    }
  }
  return legalMoves;
}

// Check if the board matches the goal state exactly
bool checkIfDone(vector<string> &lines) {
  return lines == goal;
}

// HEURISTIC: count cells that differ from goal, divide by 2.
// Each move can fix at most 2 wrong cells (moves one piece to the right position).
// This is an ADMISSIBLE heuristic (never overestimates) → IDA* is correct.
int diffFromGoal(const vector<string> &lines) {
  int diff = 0;
  for (int r = 0; r < 5; r++)
    for (int c = 0; c < 5; c++)
      if (lines[r][c] != goal[r][c])
        diff++;
  return diff / 2; // admissible lower bound on moves needed
}
