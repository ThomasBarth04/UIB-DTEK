// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`suspended-yield-iterator-close-calls-next`, () => {

    var returnCallCount = 0;

    var underlying = {
      next() {
        return { value: 123, done: false };
      },
      return() {
        returnCallCount += 1;

        // The generator state is set to "executing", so this `return()` call throws
        // a TypeError when `GeneratorResumeAbrupt` performs `GeneratorValidate`.
        expect(function () {
          it.return();
        }).toThrow(TypeError);;;

        return {};
      },
    };

    var it = Iterator.zip([underlying]);

    // Move generator into "suspended-yield" state.
    var result = it.next();
    expect(result.value).toEqual([123]);
    expect(result.done).toBe(false);

    expect(returnCallCount).toBe(0);

    // This `return()` call continues execution in the suspended generator.
    var result = it.return();
    expect(result.value).toBe(undefined);
    expect(result.done).toBe(true);

    expect(returnCallCount).toBe(1);
  });
});