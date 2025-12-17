// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

class Test214Error extends Error { }

describe('Iterator.zip', () => {
  test(`suspended-start-iterator-close-calls-next`, () => {

    var returnCallCount = 0;
    var val = 1;
    var underlying = {
      next() {
        if (val == 1) {
          val++;
          return 1;
        }
        throw new Test214Error("Unexpected call to next");
      },
      return() {
        returnCallCount += 1;

        // The generator state is already set to "completed". The generator state is
        // not "executing", so `GeneratorValidate` succeeds and `GeneratorResume`
        // returns with `CreateIteratorResultObject()`.
        var result = it.next();
        expect(result.value).toBe(undefined);
        expect(result.done).toBe(true);

        return {};
      },
    };

    var it = Iterator.zip([underlying]);

    expect(returnCallCount).toBe(0);
    it.next();

    // This `return()` call sets the generator state to "completed" and then calls
    // `IteratorClose()`.
    var result = it.return();
    expect(result.value).toBe(undefined);
    expect(result.done).toBe(true);

    expect(returnCallCount).toBe(1);
  });
});