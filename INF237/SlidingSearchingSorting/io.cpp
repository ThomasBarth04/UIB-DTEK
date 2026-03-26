#include <iostream>
#include <string>

void readSimple();
void readAsLines();
void readXTokens();

int main(void) {
  readXTokens();

  return 0;
}

void readXTokens() {
  int a, b, c;
  std::cin >> a >> b >> c;
  std::cout << a << b << b << std::endl;
}

void readSimple() {
  int x;
  std::cin >> x;               // gets first token and puts it into x
  std::cout << x << std::endl; // prints x

  while (std::cin >> x) {
    std::cout << x << std::endl; // loops all input and reassign and prits x
  }
}

void readAsLines() {
  std::string line;
  while (std::getline(std::cin, line)) {
    std::cout << line << std::endl;
  }
}
