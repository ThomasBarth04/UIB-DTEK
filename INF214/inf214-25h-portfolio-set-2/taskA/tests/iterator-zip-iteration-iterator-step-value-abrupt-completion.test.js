// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`iterator-zip-iteration-iterator-step-value-abrupt-completion`, () => {

    var modes = [
      "shortest",
      "longest",
      "strict",
    ];

    function ExpectedError() { }

    var log = [];

    var first = {
      next() {
        log.push("call first next");
        throw new ExpectedError();
      },
      return() {
        log.push("call first return");
      }
    };

    var second = {
      next() {
        log.push("unexpected call second next");
      },
      return() {
        // Called with the correct receiver and no arguments.
        expect(this).toEqual(second);
        expect(arguments.length).toBe(0);

        // NB: Log after above asserts, because failures aren't propagated.
        log.push("call second return");

        // IteratorClose ignores new exceptions when called with a Throw completion.
        throw new ExpectedError();
      }
    };

    var third = {
      next() {
        log.push("unexpected call third next");
      },
      return() {
        // Called with the correct receiver and no arguments.
        expect(this).toEqual(third);
        expect(arguments.length).toBe(0);

        // NB: Log after above asserts, because failures aren't propagated.
        log.push("call third return");

        // IteratorClose ignores new exceptions when called with a Throw completion.
        throw new Error();
      }
    };

    // Empty iterator to ensure |return| is not called for closed iterators.
    var empty = {
      next() {
        log.push("call empty next");
        return { done: true };
      },
      return() {
        log.push("call empty return");
      }
    };

    for (var mode of modes) {
      var it = Iterator.zip([first, second, third], { mode });

      expect(function () {
        it.next();
      }).toThrow(ExpectedError);

      expect(log).toEqual([
        "call first next",
        "call first return",
        "call second return",
        "call third return",
      ]);

      // Clear log.
      log.length = 0;
    }

    // This case applies only when mode is "longest".
    var it = Iterator.zip([empty, first, second, third], {});

    expect(function () {
      it.next();
    }).toThrow(ExpectedError);

    expect(log).toEqual([
      "call empty next",
      "call first next",
      "call empty return",
      "call first return",
      "call second return",
      "call third return",
    ]);
  });
});