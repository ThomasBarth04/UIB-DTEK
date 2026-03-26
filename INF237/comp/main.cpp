#include <bits/stdc++.h>
using namespace std;

int main() {
  ios::sync_with_stdio(false);
  cin.tie(nullptr);

  int n, k;
  if (!(cin >> n >> k))
    return 0;

  vector<vector<int>> children(n);
  for (int i = 1; i < n; ++i) {
    int p;
    cin >> p;
    children[p].push_back(i);
  }

  vector<int> order;
  order.reserve(n);
  vector<int> st = {0};
  while (!st.empty()) {
    int v = st.back();
    st.pop_back();
    order.push_back(v);
    for (int u : children[v])
      st.push_back(u);
  }
  reverse(order.begin(), order.end());

  const int NEG = -1000000000;
  vector<vector<int>> dp(n, vector<int>(k + 1, NEG));

  for (int v : order) {
    vector<int> cur(k + 1, NEG);
    cur[k] = 0;
    cur[0] = 1;

    for (int u : children[v]) {
      vector<int> nxt(k + 1, NEG);

      for (int d1 = 0; d1 <= k; ++d1) {
        if (cur[d1] <= NEG / 2)
          continue;

        for (int d2u = 0; d2u <= k; ++d2u) {
          if (dp[u][d2u] <= NEG / 2)
            continue;

          int d2 = d2u + 1;
          if (d2 > k)
            d2 = k;

          if (d1 < k && d2 < k && d1 + d2 < k)
            continue;

          int nd = min(d1, d2);
          nxt[nd] = max(nxt[nd], cur[d1] + dp[u][d2u]);
        }
      }

      cur.swap(nxt);
    }

    dp[v] = move(cur);
  }

  int ans = 0;
  for (int d = 0; d <= k; ++d)
    ans = max(ans, dp[0][d]);
  cout << ans << '\n';
  return 0;
}
