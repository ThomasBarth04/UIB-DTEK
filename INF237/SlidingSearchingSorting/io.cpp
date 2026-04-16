// =============================================================
// IO PATTERNS — Standard competitive programming input tricks
// =============================================================
// This file demonstrates the three most common ways to read
// input in C++ competitive programming problems.
// =============================================================

#include <iostream>
#include <string>

void readSimple();
void readAsLines();
void readXTokens();

int main(void) {
  readXTokens();

  return 0;
}

// readXTokens: Read exactly N whitespace-separated tokens in one shot.
// cin >> skips all whitespace (spaces, newlines, tabs) automatically.
// Use this when you know exactly how many values to read.
void readXTokens() {
  int a, b, c;
  cin >> a >> b >> c;
  cout << a << b << b << endl; // Note: prints b twice (likely a typo in the original)
}

// readSimple: Read tokens one at a time until EOF.
// The while (cin >> x) idiom:
//   - cin >> x tries to read a token into x
//   - Returns a truthy stream reference on success, falsy on EOF or error
//   - This is the standard way to consume an unknown number of values
void readSimple() {
  int x;
  cin >> x;               // reads first token into x
  cout << x << endl;      // prints x

  while (cin >> x) {
    cout << x << endl; // keeps reading until no more input
  }
}

// readAsLines: Read the input line by line (including spaces within lines).
// Use getline() when the problem gives structured lines, not just tokens.
// WARNING: mixing cin >> and getline() can cause bugs because cin >>
//          leaves the newline in the buffer — always cin.ignore() between them.
void readAsLines() {
  string line;
  while (getline(cin, line)) {
    cout << line << endl; // processes each line as a full string
  }
}
