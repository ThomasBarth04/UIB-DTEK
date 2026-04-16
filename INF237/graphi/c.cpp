// =============================================================
// GENERIC SEGMENT TREE — Template Class
// =============================================================
//
// A templated, reusable segment tree that works for any data type
// and any associative binary operation (sum, min, max, etc.).
//
// TEMPLATE PARAMETERS:
//   Data — the type stored at each node (e.g. int, double)
//   Op   — a callable type (lambda, function, functor) that combines
//           two Data values: Data f(Data a, Data b)
//
// NOTE — BUG in current implementation:
//   `Op f` is a constructor parameter but is NOT stored as a member.
//   This means update() and query() cannot call f — they would not compile.
//   FIX: add `Op f;` as a member field and store it in the constructor.
//
// STRUCTURE (flat 1-indexed array, leaves at [n .. 2n-1]):
//   tree[1] = root (covers all n elements)
//   tree[i] covers the range that tree[left(i)] and tree[right(i)] cover together
//   left(i)  = 2*i,   right(i) = 2*i+1,   parent(i) = i/2
//
// DIAGRAM (n=6):
//              [1]
//           /        \
//        [2]           [3]
//       /   \         /   \
//     [4]   [5]     [6]   [7]
//    /  \  /  \    /  \
//  [8] [9][10][11][12][13]   ← leaves 0..5 at indices n..n+5
//
// OPERATIONS:
//   update(i, value) — set leaf i to value, O(log n)
//   query(l, r)      — apply Op over [l, r], O(log n)
//   lookup(i)        — return leaf i value, O(1)
// =============================================================

#include <vector>
#include <cmath>
#include <string>
#include <iostream>

using namespace std;

template <typename Data, typename Op>
class SegmentTree{
    vector<Data> tree;
    int n;
    bool incl; // if true, query() is inclusive on both ends [l, r]; otherwise [l, r)

    public:
    // Constructor: builds the tree from the initial data array.
    // f: the combining operation (e.g. sum, min, max).
    // NOTE: f is used here but not stored — update/query cannot use it (see bug note above).
    SegmentTree(vector<Data> data, bool inclusive, Op f){
        n = data.size();
        incl = inclusive;
        // Allocate 2^(ceil(log2(n))+1) nodes to ensure the tree is complete
        tree = vector<Data>(pow(2,ceil(log2(n))+1), 0);

        // Place data in the leaf layer starting at index n
        for (int i {n}; i < 2 * n; i++){
            tree[i] = data[i-n];
        }

        // Build internal nodes bottom-up by combining children with f
        for (int i {n-1}; i > 0; i--){
            tree[i] = f(tree[left(i)], tree[right(i)]);
        }
    };

    int left(int i)  { return 2 * i; }     // left child index
    int right(int i) { return 2 * i + 1; } // right child index
    int parent(int i){ return i / 2; }      // parent index
    int index(int i) { return n + i; }      // 0-based position → leaf index
    Data lookup(int i){ return tree[index(i)]; } // direct leaf access

    // Point update: set leaf i to value, then rebuild ancestors.
    void update(int i, Data value){
        int idx = index(i);
        tree[idx] = value;
        // Walk up recomputing each ancestor (cannot call f here — bug)
        while ((idx = parent(idx)) > 0){
            tree[idx] = f(tree[left(idx)], tree[right(idx)]); // f not in scope!
        }
    }

    void print(){
        for (auto n : tree) cout << n << ' ';
        cout << endl;
    }

    // Range query over [l, r].
    // Uses the "two-pointer from leaves" technique:
    //   l and r start at the leaf layer, then walk up.
    //   At each level, if l is a right child → include it, advance l.
    //                  if r is a left child  → include it, retreat r.
    Data query(int l, int r){
        l = index(l);
        r = index(r);
        Data ret {tree[l]};
        if (l == r) return ret; // single element
        if (incl) ret = f(ret, tree[r]); // include right endpoint if inclusive
        int pl, pr;
        while (true){
            pl = parent(l);
            pr = parent(r);
            if (pl == pr) return ret; // same parent → done
            if (l % 2 == 0) ret = f(ret, tree[right(pl)]); // l is left child → add sibling
            if (r % 2 == 1) ret = f(ret, tree[left(pr)]);  // r is right child → add sibling
            l = pl;
            r = pr;
        }
    }
};

int main(){
    vector<int> arr {0, 1, 2, 3, 4, 5};
    // Example: build a sum segment tree over arr
    SegmentTree st = SegmentTree(arr, true, [](int a, int b){
        return a + b; // combining operation = addition
    });
}
