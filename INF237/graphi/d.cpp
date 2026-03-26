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
    int total {0};
    vector<pair<int,pair<int,int>>> xs(n);
    vector<pair<int,pair<int,int>>> ys;
    for (int i {0}; i < n; i++) {
        cin >> p >> r >> d;
        xs[i] = {r, {p, d}};
        total += r;
    }

    // int prev_best = -1;
    // int time {0};
    // int total_cost {0};
    // bool first = true;
    // while (n > 1) {
    //     int best = 999999999;
    //     int best_i = -1;
    //     ys = {};
    //     for (int i {0}; i < n; i++) {
    //         if (i == prev_best) continue;
    //         auto [r, pd] = xs[i];
    //         auto [p, d] = pd;
    //         int cost = (total - r) * d;
    //         if (cost < best) {
    //             best = cost;
    //             best_i = i;
    //         }
    //         ys.push_back(xs[i]);
    //     }
    //     // cout << "time: " << time << '\n'; 
    //     // cout << "picking " << best_i << '\n';
    //     // cout << "adding " << xs[best_i].second.first + time * xs[best_i].first << '\n';
    //     prev_best = best_i;
    //     total -= xs[best_i].first;
    //     total_cost += xs[best_i].second.first + time * xs[best_i].first;
    //     time += xs[best_i].second.second;
    //     xs = ys;
    //     if (!first) n--;
    //     first = false;
    // }

    // cout << total_cost << '\n';

    cout << "total is " << total << '\n';
    for (auto [r, pd] : xs) {
        auto [p, d] = pd;
        cout << "cost of picking " << p << ", " << r << ", " << d << " is " << d * (total - r) << '\n';
    }
    sort(xs.begin(), xs.end(), [total](pair<int,pair<int,int>>& a, pair<int,pair<int,int>>& b) { 
        return a.second.second * (total-a.first) < b.second.second * (total-b.first);
    });

    int time {0};
    int cost {0};
    for (auto [r, pd] : xs) {
        auto [p, d] = pd;
        // cout << "choosing " << p << ", " << r << ", " << d << '\n';
        cost += p + r*time;
        time += d;
    }

    cout << cost << '\n';

}

