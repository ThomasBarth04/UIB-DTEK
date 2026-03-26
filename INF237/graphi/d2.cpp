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
using u64 = uint64_t;

int main() {
    cin.tie(nullptr);
    ios::sync_with_stdio(false);
    cin.exceptions(ios::failbit);
    cout << setprecision(10) << fixed;

    u64 n, p, r, d;
    cin >> n;
    u64 total_rate {0};
    u64 ret {0};
    vector<vector<u64>> xss(10001);
    vector<bool> seen(10001);
    set<u64> ds;
    for (u64 i {0}; i < n; i++) {
        cin >> p >> r >> d;
        ret += p;
        xss[d].push_back(r);
        total_rate += r;
        if (!seen[d]) {
            seen[d] = true;
            ds.insert(d);
        }
    }
    for (u64 d : ds) {
        sort(xss[d].begin(), xss[d].end());
    }
    
    // cout << "initial ret is " << ret << '\n';
    u64 time {0};
    while (ds.size()) {
        u64 best_d = -1;
        u64 best_cost = -1;

        for (u64 d : ds) {
            u64 r = xss[d][xss[d].size()-1];
            u64 cost = d * (total_rate - r);
            // cout << "this cost: " << cost << '\n';
            if (best_cost == -1 || cost < best_cost) {
                best_cost = cost;
                best_d = d;
            }
            // cout << "best cost: " << best_cost << '\n';
        }
        u64 r = *xss[best_d].rbegin();
        // ret += best_cost;
        ret += best_d * (total_rate - r);
        // cout << "new ret is " << ret << " after picking r=" << r << '\n';
        time += best_d;
        total_rate -= r;

        xss[best_d].pop_back();
        if (xss[best_d].size() == 0) {
            ds.erase(best_d);
        }
    }

    cout << ret << '\n';
}

