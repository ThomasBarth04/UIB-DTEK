// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`padding-iteration-iterator-step-value-abrupt-completion`, () => {

    class Test214Error extends Error { }

    var log = [];

    var first = {
      next() {
        log.push("unexpected call to next method");
      },
      return() {
        // Called with the correct receiver and no arguments.
        expect(this).toBe(first);
        expect(arguments.length).toBe(0);

        // NB: Log after above asserts, because failures aren't propagated.
        log.push("first return");

        // This exception is ignored.
        throw new Test214Error();
      }
    };

    var second = {
      next() {
        log.push("unexpected call to next method");
      },
      return() {
        // Called with the correct receiver and no arguments.
        expect(this).toBe(second);
        expect(arguments.length).toBe(0);

        // NB: Log after above asserts, because failures aren't propagated.
        log.push("second return");

        // This exception is ignored.
        throw new Test214Error();
      }
    };

    var third = {
      next() {
        log.push("unexpected call to next method");
      },
      get return() {
        // Called with the correct receiver and no arguments.
        expect(this).toBe(third);
        expect(arguments.length).toBe(0);

        // NB: Log after above asserts, because failures aren't propagated.
        log.push("third return");

        // This exception is ignored.
        throw new Test214Error();
      }
    };

    function ExpectedError() { }

    // Padding iterator throws from |next|.
    var padding = {
      [Symbol.iterator]() {
        return this;
      },
      next() {
        throw new ExpectedError();
      },
      return() {
        log.push("unexpected call to return method");
      },
    };

    expect(function () {
      Iterator.zip([first, second, third], { padding }).next();
    }).toThrow(ExpectedError);

    expect(log).toEqual([
      "first return",
      "second return",
      "third return",
    ]);

    // Clear log
    log.length = 0;

    // Padding iterator throws from |done|.
    var padding = {
      [Symbol.iterator]() {
        return this;
      },
      next() {
        return {
          get done() {
            throw new ExpectedError();
          },
          get value() {
            log.push("unexpected access to value");
          },
        };
      },
      return() {
        log.push("unexpected call to return method");
      },
    };

    expect(function () {
      Iterator.zip([first, second, third], { padding }).next();
    }).toThrow(ExpectedError);

    expect(log).toEqual([
      "first return",
      "second return",
      "third return",
    ]);


    // Clear log
    log.length = 0;

    // Padding iterator throws from |value|.
    var padding = {
      [Symbol.iterator]() {
        return this;
      },
      next() {
        return {
          done: false,
          get value() {
            throw new ExpectedError();
          },
        };
      },
      return() {
        log.push("unexpected call to return method");
      },
    };

    expect(function () {
      Iterator.zip([first, second, third], { padding }).next();
    }).toThrow(ExpectedError);

    expect(log).toEqual([
      "first return",
      "second return",
      "third return",
    ]);
  });
});