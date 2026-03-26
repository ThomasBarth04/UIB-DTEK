#include <iostream>
#include <vector>

using namespace std;

int n;
vector<int> tree;

void update(int pos, int value) {
  pos += n;
  tree[pos] = value;

  while (pos > 1) {
    pos /= 2;
    tree[pos] = tree[2 * pos] + tree[2 * pos + 1];
  }
}

int sum(int l, int r) {
  l += n;
  r += n;
  int result = 0;

  while (l <= r) {
    if (l % 2 == 1)
      result += tree[l++];
    if (r % 2 == 0)
      result += tree[r--];
    l /= 2;
    r /= 2;
  }
  return result;
}

int main() {
  int t;
  cin >> t;

  for (int i = 0; i < t; i++) {
    int m, r;
    cin >> m >> r;
    n = m + r;
    tree.assign(2 * n, 0);

    vector<int> pos(m);
    for (int i = 0; i < m; i++) {
      pos[i] = i + r;
    }

    for (int i = 0; i < m; i++) {
      tree[i + r + n] = 1;
    }
    for (int i = n - 1; i > 0; i--) {
      tree[i] = tree[2 * i] + tree[2 * i + 1];
    }

    int top = r - 1;
    for (int i = 0; i < r; i++) {
      int movie;
      cin >> movie;
      int moviePos = pos[movie - 1];
      int result = sum(0, moviePos - 1);
      cout << result << " ";
      update(moviePos, 0);
      update(top, 1);
      pos[movie - 1] = top;

      top--;
    }
    cout << endl;
  }

  return 0;
}
