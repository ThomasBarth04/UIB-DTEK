#include <deque>
#include <iostream>
#include <vector>
using namespace std;

int main(int argc, char *argv[]) {

  vector<int> list = {8, 9, 6, 1, 2, 5, 7, 2, 3, 7};
  deque<int> max;
  int windowSize = 3;

  // first window
  for (int i = 0; i < windowSize; i++) {
    while (!max.empty() && list[max.back()] <= list[i]) {
      max.pop_back();
    }
    max.push_back(i);
  }
  cout << max.front() << endl;

  // move window (i = end of window)
  for (int i = windowSize; i < list.size(); i++) {
    while (!max.empty() && max.front() <= i - windowSize) {
      max.pop_front();
    }

    while (!max.empty() && list[max.back()] < list[i]) {
      max.pop_back();
    }
    max.push_back(i);
    cout << max.front() << endl;
  }

  return 0;
}
