// =============================================================
// SCRATCH / TEST FILE — XOR / Bitwise trick
// =============================================================
//
// BITWISE XOR TRICK used in 2-SAT literal encoding:
//   neg(x) = x ^ 1
//
//   If x is a literal index:
//   - Even indices (x = 2k) represent the POSITIVE literal for variable k
//   - Odd  indices (x = 2k+1) represent the NEGATIVE literal for variable k
//   - XOR with 1 flips the last bit: even ↔ odd → toggles positive ↔ negative
//
//   Example: x = 4 (positive literal for variable 2)
//            x ^ 1 = 5 (negative literal for variable 2)
//            x = 5 (negative literal) → x ^ 1 = 4 (back to positive)
//
// This is used in the 2-SAT solver (wedding.cpp) to negate a literal cheaply.
// =============================================================

#include <iostream>

using namespace std;

int main() {

  int x = 5; // represents some literal index (odd = negative literal)

  // XOR with 1 gives the NEGATED literal (flips between positive and negative)
  cout << (x ^ 1) << endl; // output: 4 (the positive version of this literal)
  return 0;
}
