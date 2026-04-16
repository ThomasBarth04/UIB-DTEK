// =============================================================
// JABUKE — Triangle Area + Points Inside Triangle (Geometry)
// =============================================================
//
// PROBLEM: Given a triangle (a, b, c) and N query points,
//          compute:
//   1. The area of the triangle.
//   2. How many query points are strictly inside the triangle.
//
// KEY TOOLS — Cross Product and Orientation:
//
//   orient(a, b, c) = cross product of vectors (b-a) and (c-a)
//                   = (b.x-a.x)*(c.y-a.y) - (b.y-a.y)*(c.x-a.x)
//   If orient > 0 → c is to the LEFT of line a→b  (counter-clockwise)
//   If orient < 0 → c is to the RIGHT              (clockwise)
//   If orient = 0 → c is collinear with a and b
//
// TRIANGLE AREA:
//   area = |orient(a, b, c)| / 2
//   (The cross product magnitude = parallelogram area; triangle = half of that)
//
// POINT IN TRIANGLE:
//   A point P is inside triangle (a, b, c) if it is on the SAME SIDE of
//   each edge as the interior. Since we normalise the triangle to CCW order,
//   P must be to the LEFT (or on) each directed edge.
//
//   in_angle(a, b, c, d) checks:
//     orient(a, b, d) >= 0  (d is left of or on edge a→b)
//     orient(a, c, d) <= 0  (d is right of or on edge a→c, opposite direction)
//   Together: d is in the "wedge" between rays a→b and a→c.
//
//   The full point-in-triangle test uses two in_angle checks from different vertices.
//   (Note: this tests P inside the half-plane defined by each edge pair.)
//
// DIAGRAM:
//        b
//       / \
//      /   \
//     / P?  \
//    a-------c
//
//   CCW order: a, b, c. For P inside: orient(a,b,P)>0 and orient(b,c,P)>0 and orient(c,a,P)>0
//
// =============================================================

#include <iostream>

using namespace std;

bool in_angle(pair<int, int> a, pair<int, int> b, pair<int, int> c,
              pair<int, int> d);
long long orient(pair<int, int> a, pair<int, int> b, pair<int, int> c);

int main(int argc, char *argv[]) {
  pair<int, int> a;
  pair<int, int> b;
  pair<int, int> c;
  cin >> a.first >> a.second;
  cin >> b.first >> b.second;
  cin >> c.first >> c.second;

  // Ensure the triangle is in counter-clockwise (CCW) order.
  // orient < 0 means CW → swap b and c to make it CCW.
  if (orient(a, b, c) < 0)
    swap(b, c);

  // Area = |cross product| / 2
  double area = abs(orient(a, b, c)) / 2.0;

  int N;
  cin >> N;

  int count = 0;

  for (int i = 0; i < N; ++i) {
    pair<int, int> P;
    cin >> P.first >> P.second;

    // Check if P is inside the triangle using two angular checks.
    // in_angle(a, b, c, P): P is in the "wedge" from vertex a, between a→b and a→c
    // Combined: P must satisfy both wedge conditions simultaneously.
    if (in_angle(a, b, c, P) && in_angle(c, a, b, P)) {
      count++;
    }
  }

  cout << fixed;
  cout.precision(1);
  cout << area << "\n";
  cout << count << "\n";

  return 0;
}

// Vector subtraction: b - a
pair<int, int> subtract(pair<int, int> a, pair<int, int> b) {
  return {a.first - b.first, a.second - b.second};
}

// 2D cross product of vectors a and b
// cross(a, b) = a.x*b.y - a.y*b.x
// Positive = b is CCW from a; Negative = b is CW from a
long long cross(pair<int, int> a, pair<int, int> b) {
  return a.first * b.second - a.second * b.first;
}

// Signed area of triangle (a, b, c) × 2.
// Positive → CCW orientation, Negative → CW orientation, 0 → collinear.
long long orient(pair<int, int> a, pair<int, int> b, pair<int, int> c) {
  return cross(subtract(b, a), subtract(c, a));
}

// Returns true if point d is in the angular "wedge" formed at vertex a,
// between rays a→b and a→c (for a CCW triangle, this means d is between
// the two sides meeting at a).
bool in_angle(pair<int, int> a, pair<int, int> b, pair<int, int> c,
              pair<int, int> d) {
  return orient(a, b, d) >= 0 && orient(a, c, d) <= 0;
}
