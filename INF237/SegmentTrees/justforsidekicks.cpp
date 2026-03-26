#include <array>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

int n;
vector<array<int, 6>> tree;
vector<long long> gemValue(6);
void update(int pos, int newGem);
long long sum(int l, int r);

int main() {
  int q;
  cin >> n >> q;

  for (int i = 0; i < 6; i++)
    cin >> gemValue[i];

  string s;
  cin >> s;

  tree.resize(2 * n);

  for (int i = 0; i < n; i++) {
    tree[i + n].fill(0);
    tree[i + n][s[i] - '1'] += 1;
  }

  for (int i = n - 1; i > 0; i--) {
    for (int g = 0; g < 6; g++) {
      tree[i][g] = (tree[2 * i][g] + tree[2 * i + 1][g]);
    }
  }

  // for (auto arr : tree) {
  //   for (int i : arr) {
  //     cout << i << " ";
  //   }
  //   cout << endl;
  // }

  for (int i = 0; i < q; i++) {
    int a;
    cin >> a;

    if (a == 1) {
      int k, p;
      cin >> k >> p;
      k--;
      p--;
      update(k, p);
    } else if (a == 2) {
      int p;
      long long v;
      cin >> p >> v;
      p--;
      gemValue[p] = v;

    } else {
      int l, r;
      cin >> l >> r;
      l--;
      r--;
      cout << sum(l, r) << "\n";
    }
  }
  // update(1, 69);
  // first = true;
  // for (auto &pair : tree) {
  //   if (first) {
  //     first = false;
  //     continue;
  //   }
  //
  //   if (pair.first == -1) {
  //     cout << "range with sum: " << pair.second << endl;
  //   } else {
  //     cout << "gem(" << pair.first << ") with value: " << pair.second <<
  //     endl;
  //   }
  // }
}

void update(int pos, int newGem) {
  pos += n;
  tree[pos].fill(0);
  tree[pos][newGem] = 1;

  while (pos > 1) {
    pos /= 2;
    for (int i = 0; i < 6; i++) {
      tree[pos][i] = tree[2 * pos][i] + tree[2 * pos + 1][i];
    }
  }
}

long long sum(int l, int r) {
  l += n;
  r += n;

  long long total = 0;

  while (l <= r) {
    if (l % 2 == 1) {
      for (int g = 0; g < 6; g++) {
        total += gemValue[g] * tree[l][g];
      }
      l++;
    }
    if (r % 2 == 0) {
      for (int g = 0; g < 6; g++) {
        total += gemValue[g] * tree[r][g];
      }
      r--;
    }
    l /= 2;
    r /= 2;
  }

  return total;
}
