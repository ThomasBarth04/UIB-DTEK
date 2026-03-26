#include <iostream>
#include <vector>

using namespace std;

int n;
vector<int> tree;

// point update
void update(int pos, int value) {
  pos += n;
  tree[pos] = value;

  while (pos > 1) {
    pos /= 2;
    tree[pos] = tree[2 * pos] + tree[2 * pos + 1];
  }
}

// range sum [l, r] (0-based inclusive)
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

    vector<int> pos(m + 1);

    for (int i = 1; i <= m; i++) {
      pos[i] = r + i - 1;
      update(pos[i], 1);
    }

    int currentTop = r - 1; // next free top slot

    for (int i = 0; i < r; i++) {
      int movie;
      cin >> movie;

      int moviePos = pos[movie];

      // count movies above it
      int result = sum(0, moviePos - 1);
      cout << result << " ";

      // remove from old position
      update(moviePos, 0);

      // move to top
      pos[movie] = currentTop;
      update(currentTop, 1);

      currentTop--;
    }

    cout << "\n";
  }

  return 0;
}
