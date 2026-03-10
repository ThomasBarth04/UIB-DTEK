#include <iostream>
#include <vector>

using namespace std;

bool solveTest(vector<string> lines, int n, int max);
bool checkIfDone(vector<string> &lines);
int diffFromGoal(const vector<string> &lines);
vector<pair<int, int>> getPossibleMoves(vector<string> &lines,
                                        pair<int, int> blank);
vector<string> goal = {"11111", "01111", "00 11", "00001", "00000"};

int main() {
  int n;
  cin >> n;
  cin.ignore();
  for (int i = 0; i < n; i++) {
    vector<string> l(5);

    for (int j = 0; j < 5; j++) {
      getline(cin, l[j]);
    }

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

bool solveTest(vector<string> lines, int n, int max) {
  if (n > max) {
    return false;
  }

  if (n > 10) {
    return false;
  }

  int diff = diffFromGoal(lines);

  if (diff + n > max) {
    return false;
  }

  if (checkIfDone(lines)) {
    cout << "Solvable in " << n << " move(s)." << endl;
    return true;
  }

  int empty_r = -1;
  int empty_c = -1;

  for (int r = 0; r < 5; r++) {
    for (int c = 0; c < 5; c++) {
      if (lines[r][c] == ' ') {
        empty_r = r;
        empty_c = c;
      }
    }
  }

  vector<pair<int, int>> moves = getPossibleMoves(lines, {empty_r, empty_c});

  for (pair<int, int> move : moves) {

    swap(lines[empty_r][empty_c], lines[move.first][move.second]);

    if (solveTest(lines, n + 1, max)) {
      return true;
    };
    swap(lines[empty_r][empty_c], lines[move.first][move.second]);
  }

  return false;
}

vector<pair<int, int>> getPossibleMoves(vector<string> &lines,
                                        pair<int, int> blank) {

  vector<pair<int, int>> kMoves = {{-2, -1}, {-2, 1}, {-1, -2}, {-1, 2},
                                   {1, -2},  {1, 2},  {2, -1},  {2, 1}};

  vector<pair<int, int>> legalMoves;
  int blank_r = blank.first;
  int blank_c = blank.second;
  for (int i = 0; i < 8; i++) {
    int r = blank_r + kMoves[i].first;
    int c = blank_c + kMoves[i].second;

    if (r < 0 || r > 4 || c < 0 || c > 4) {
      continue;
    }

    if (lines[r][c] == '0' || lines[r][c] == '1') {
      legalMoves.push_back({r, c});
    }
  }
  return legalMoves;
}

bool checkIfDone(vector<string> &lines) {
  if (lines == goal) {
    return true;
  }
  return false;
}
int diffFromGoal(const vector<string> &lines) {
  int diff = 0;
  for (int r = 0; r < 5; r++)
    for (int c = 0; c < 5; c++)
      if (lines[r][c] != goal[r][c])
        diff++;
  return diff / 2;
}
