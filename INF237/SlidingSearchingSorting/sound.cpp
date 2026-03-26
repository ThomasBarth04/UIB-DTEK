#include <deque>
#include <iostream>
#include <vector>
using namespace std;

int main(void) {

  int n, m, c;
  cin >> n >> m >> c;

  vector<int> sounds(n);
  for (int i = 0; i < n; i++) {
    cin >> sounds[i];
  }

  deque<int> max;
  deque<int> min;
  vector<int> res;

  // første vindu:
  for (int i = 0; i < m; i++) {
    while (!max.empty() && sounds[max.back()] <= sounds[i]) {
      max.pop_back();
    }
    max.push_back(i);

    while (!min.empty() && sounds[min.back()] >= sounds[i]) {
      min.pop_back();
    }
    min.push_back(i);
  }
  if (sounds[max.front()] - sounds[min.front()] <= c) {
    res.push_back(1); // 1 index ffs
  }

  // (i = end av window)
  for (int i = m; i < sounds.size(); i++) {
    while (!max.empty() && max.front() <= i - m) {
      max.pop_front();
    }

    while (!max.empty() && sounds[max.back()] <= sounds[i]) {
      max.pop_back();
    }
    max.push_back(i);

    while (!min.empty() && min.front() <= i - m) {
      min.pop_front();
    }

    while (!min.empty() && sounds[min.back()] >= sounds[i]) {
      min.pop_back();
    }
    min.push_back(i);

    if (sounds[max.front()] - sounds[min.front()] <= c) {
      res.push_back((i - m) + 2);
    }
  }

  if (res.empty()) {
    cout << "NONE" << endl;
  } else {
    for (int i : res) {
      cout << i << endl;
    }
  }
}
