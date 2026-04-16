// =============================================================
// ERRANDS (GREEDY SCHEDULING) — Minimize Weighted Completion Cost
// =============================================================
//
// PROBLEM: n tasks, each with:
//   p = base cost to complete (flat fee)
//   r = rate (cost per unit time you've already spent before starting it)
//   d = duration (how long it takes)
//
// Total cost for a task = p + r * (time when you START it)
// Goal: order tasks to MINIMISE the total cost.
//
// GREEDY KEY INSIGHT:
//   Consider two adjacent tasks A and B. We choose A before B if:
//     cost(A then B) < cost(B then A)
//     pA + rA*t + pB + rB*(t + dA) < pB + rB*t + pA + rA*(t + dB)
//     rB * dA < rA * dB
//     dA / rA < dB / rB     (if r≠0)
//   i.e., sort by d / r (ascending) is NOT quite right here;
//   the correct criterion is: rB * dA < rA * dB, or equivalently d*r compared.
//
// ACTUAL SORT CRITERION used here:
//   d * (total_rate - r) — a heuristic sort that minimises the "delay cost"
//   imposed on all remaining tasks by choosing this task next.
//   (total_rate = sum of all r values; choosing a task with high r "saves"
//    other tasks from paying for r's contribution to future delays)
//
// ALGORITHM:
//   1. Compute total_rate = sum of all r values.
//   2. Sort tasks by: d * (total_rate - r)  ascending
//      (tasks that impose low delay on others go first)
//   3. Process tasks in sorted order; accumulate cost = p + r * current_time.
//
// TIME: O(n log n)
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

    int n, p, r, d;
    cin >> n;
    int total {0}; // sum of all rates r (used to compute sort key)

    // Store each task as {r, {p, d}}
    vector<pair<int,pair<int,int>>> xs(n);
    for (int i {0}; i < n; i++) {
        cin >> p >> r >> d;
        xs[i] = {r, {p, d}};
        total += r; // accumulate total rate
    }

    // Debug: print costs for each task if chosen next
    cout << "total is " << total << '\n';
    for (auto [r, pd] : xs) {
        auto [p, d] = pd;
        // d * (total - r) = delay imposed on all OTHER tasks' rates if we pick this last
        cout << "cost of picking " << p << ", " << r << ", " << d << " is " << d * (total - r) << '\n';
    }

    // Sort by d * (total - r): tasks that cause least harm to others go first
    sort(xs.begin(), xs.end(), [total](pair<int,pair<int,int>>& a, pair<int,pair<int,int>>& b) {
        return a.second.second * (total-a.first) < b.second.second * (total-b.first);
    });

    int time {0};  // current time (increases as we complete tasks)
    int cost {0};  // running total cost

    for (auto [r, pd] : xs) {
        auto [p, d] = pd;
        cost += p + r * time; // base cost + rate × time already spent
        time += d;            // this task takes d time units
    }

    cout << cost << '\n';
}
