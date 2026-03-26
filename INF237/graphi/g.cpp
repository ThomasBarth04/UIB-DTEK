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

    multiset<int> layers;
    vector<int> xs;
    int n, p, a;
    char c;
    int sum {0};
    cin >> n;
    for (int i {0}; i < n; i++) {
        cin >> p;
        xs.push_back(p);
        layers.insert(p);
    }
    cin >> n;
    for (int i {0}; i < n; i++) {
        cin >> c;
        if (c == '+') {
            cin >> a;
            layers.insert(a);
            xs.push_back(a);
        }
        else {
            // layers.erase
            auto itr = layers.find(xs[xs.size()-1]);
            if(itr!=layers.end()){
                layers.erase(itr);
            }
            // layers.erase(, false);
            xs.pop_back();
        }
        sum += *(layers.rbegin());
    }
    cout << sum << '\n';
    return 0;
}
