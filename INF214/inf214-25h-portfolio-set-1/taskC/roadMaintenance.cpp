#include "alang.h"
using alang::global_mutex;

// Semaphores
semaphore super{1};
semaphore clean{0};
semaphore paint{0};
semaphore sensor{0};

static inline void placeTwoAndSignal(int r) {
  switch (r) {
  case 1:
    produce("S", "paint");
    produce("S", "sensor");
    clean.V();
    break;
  case 2:
    produce("S", "cleaning solution");
    produce("S", "sensor");
    paint.V();
    break;
  case 3:
    produce("S", "cleaning solution");
    produce("S", "paint");
    sensor.V();
    break;
  default:
    break;
  }
}
void processSupervisor() {
  super.P();
  int randNum = randomProcess();
  placeTwoAndSignal(randNum);
}

void processCleaningSolution() {
  clean.P();
  produce("A", "cleaning solution");
  assemble("A");
  super.V();
}

void processPaint() {
  paint.P();
  produce("B", "paint");
  assemble("B");
  super.V();
}

void processSensor() {
  sensor.P();
  produce("C", "sensor");
  assemble("C");
  super.V();
}
