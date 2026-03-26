
#include <iostream>
#include <vector>
using namespace std;

int main(int argc, char *argv[]) {
  int a, b, c, d, e, f, g, h;
  cin >> a >> b >> c >> d >> e >> f >> g >> h;
  // cout << a << " " << b << " " << c << " " << d << " " << e << " " << f << "
  // "
  //      << g << " " << h << " ";

  int width = c - a + 1;
  int height = d - b + 1;

  int m1x = e - a, m1y = f - b;
  int m2x = g - a, m2y = h - b;

  vector<vector<long long>> map(width, vector<long long>(height, 0));
  map[0][0] = 1;
  // for (int i = 0; i < cols; i++) {
  //   for (int j = 0; j < rows; j++) {
  //     cout << map[i][j] << " ";
  //   }
  //   cout << endl;
  // }
  //
  for (int x = 0; x < width; x++) {
    for (int y = 0; y < height; y++) {
      if (x == 0 && y == 0) {
        continue;
      }
      if ((x == m1x && y == m1y) || (x == m2x && y == m2y)) {
        map[x][y] = 0;
        continue;
      }

      if (x > 0) {
        map[x][y] += map[x - 1][y];
      }
      if (y > 0) {
        map[x][y] += map[x][y - 1];
      }
    }
  }

  cout << map[width - 1][height - 1] << endl;
  return 0;
}
