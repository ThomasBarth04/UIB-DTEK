// =============================================================
// LAYERS / STACK PROBLEM — Multiset for Dynamic Maximum
// =============================================================
//
// PROBLEM: You have a sequence of "layer" values. Operations:
//   '+' a  — push value a onto the stack and add it to the multiset
//   '-'    — pop the top value from the stack and remove from multiset
//   After each operation, add the current MAXIMUM value to a running sum.
//
// DATA STRUCTURE:
//   - A vector<int> xs acts as the stack (push_back / pop_back).
//   - A multiset<int> layers maintains all current values and supports
//     fast maximum lookup via layers.rbegin() (largest element).
//   - multiset allows duplicate values and O(log n) insert/erase.
//
// WHY MULTISET?
//   If we just used a variable to track the max, removing an element
//   might invalidate it (we'd need to rescan). The multiset always
//   keeps elements sorted, so rbegin() gives the current max in O(1).
//
// EXAMPLE:
//   Initial layers: [3, 1, 4]   multiset: {1, 3, 4}   max=4
//   Op: + 2  → xs=[3,1,4,2],   multiset: {1,2,3,4}   sum += 4
//   Op: -    → pop 2, xs=[3,1,4], multiset: {1,3,4}  sum += 4
//   Op: + 5  → xs=[3,1,4,5],   multiset: {1,3,4,5}   sum += 5
//   ...
// =============================================================

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <map>
#include <queue>
#include <set>
#include <algorithm>
#include <cstdint>

using namespace std;

int main() {
    cin.tie(nullptr);
    ios::sync_with_stdio(false);
    cin.exceptions(ios::failbit);
    cout << setprecision(10) << fixed;

    multiset<int> layers; // sorted multiset: rbegin() = current maximum
    vector<int> xs;       // stack of all pushed values (to know what to pop)
    int n, p, a;
    char c;
    int sum {0};

    // Read initial n layers
    cin >> n;
    for (int i {0}; i < n; i++) {
        cin >> p;
        xs.push_back(p);      // add to stack
        layers.insert(p);     // add to multiset
    }

    // Read n operations
    cin >> n;
    for (int i {0}; i < n; i++) {
        cin >> c;
        if (c == '+') {
            // Push a new value
            cin >> a;
            layers.insert(a);   // add to sorted multiset
            xs.push_back(a);    // record in stack
        }
        else {
            // Pop the top value (most recently pushed element)
            // Find and erase exactly one copy of the top value from the multiset
            auto itr = layers.find(xs[xs.size()-1]);
            if (itr != layers.end()){
                layers.erase(itr); // erase(iterator) removes exactly one copy
                                   // (vs erase(value) which removes ALL copies)
            }
            xs.pop_back(); // remove from stack
        }
        // After each operation, accumulate the current maximum
        sum += *(layers.rbegin()); // rbegin() points to the largest element
    }
    cout << sum << '\n';
    return 0;
}
