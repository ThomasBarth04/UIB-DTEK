// =============================================================
// ERRANDS SCHEDULING — Greedy Minimise Weighted Completion Time
// =============================================================
//
// PROBLEM: n tasks, each with:
//   p = base completion cost (paid once, at the time of selection)
//   r = rate (multiplied by the total time elapsed before this task starts)
//   d = duration (time consumed by this task)
//
// Total cost = Σ (p_i + r_i * start_time_i)
//   where start_time_i = sum of durations of all tasks scheduled before i.
//
// GOAL: Choose the order of tasks to MINIMISE total cost.
//
// GREEDY PROOF (exchange argument):
//   Consider two adjacent tasks A (scheduled first) and B:
//   Cost(A before B) = pA + rA*t + pB + rB*(t + dA)
//   Cost(B before A) = pB + rB*t + pA + rA*(t + dB)
//   A before B is better iff:
//     rB * dA < rA * dB
//     ↔  dA/rA < dB/rB   (sort by d/r ascending, avoiding division with d*r comparison)
//
// IMPLEMENTATION:
//   This file uses a more efficient bucket/set approach for the greedy:
//   - Group tasks by their duration d (xss[d] = list of rates r for tasks with that d).
//   - At each step, pick the task with the lowest d * (total_rate - r).
//     The "cost" of picking a task = how much we delay all REMAINING tasks.
//     Picking task with (d, r) costs d * (total_rate - r) extra to all remaining tasks.
//   - After picking, subtract r from total_rate, remove from bucket.
//
// WHY d * (total_rate - r)?
//   total_rate - r = sum of rates of all OTHER tasks.
//   d = how long we delay them.
//   So d * (total_rate - r) = total extra cost we impose by scheduling this task next.
//
// TIME: O(n log n)  (sorting and greedy selection)
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
using u64 = uint64_t;

int main() {
    cin.tie(nullptr);
    ios::sync_with_stdio(false);
    cin.exceptions(ios::failbit);
    cout << setprecision(10) << fixed;

    u64 n, p, r, d;
    cin >> n;

    u64 total_rate {0}; // sum of all r values (reduces as we schedule tasks)
    u64 ret {0};        // running total cost (start with sum of all p values)

    // Group tasks by duration d: xss[d] = list of rates r for tasks with this d
    vector<vector<u64>> xss(10001);
    vector<bool> seen(10001);   // which durations have been seen
    set<u64> ds;                // set of distinct durations present

    for (u64 i {0}; i < n; i++) {
        cin >> p >> r >> d;
        ret += p;           // base cost: always paid (order-independent)
        xss[d].push_back(r); // group rate by duration
        total_rate += r;
        if (!seen[d]) {
            seen[d] = true;
            ds.insert(d); // track distinct durations
        }
    }

    // Sort each bucket of rates in ascending order
    // (we'll pick the LARGEST rate task from each bucket, so sort ascending and pop_back)
    for (u64 d : ds) {
        sort(xss[d].begin(), xss[d].end());
    }

    u64 time {0}; // current elapsed time

    // Greedy: repeatedly pick the task that minimises additional delay cost
    while (ds.size()) {
        u64 best_d = -1;
        u64 best_cost = -1;

        // Find which (duration, rate) pair has the minimum "delay cost"
        // For each duration group, consider its highest-rate task (best candidate)
        for (u64 d : ds) {
            u64 r = xss[d][xss[d].size()-1]; // largest rate in this duration group
            u64 cost = d * (total_rate - r);  // delay imposed on all other tasks
            if (best_cost == -1 || cost < best_cost) {
                best_cost = cost;
                best_d = d;
            }
        }

        // Pick the best task: highest-rate task from the best duration bucket
        u64 r = *xss[best_d].rbegin();
        ret += best_d * (total_rate - r); // add the delay cost to total
        time += best_d;                   // advance time by this task's duration
        total_rate -= r;                  // this task's rate no longer delays others

        // Remove the chosen task from its bucket
        xss[best_d].pop_back();
        if (xss[best_d].size() == 0) {
            ds.erase(best_d); // no more tasks with this duration
        }
    }

    cout << ret << '\n'; // minimum total cost
}
