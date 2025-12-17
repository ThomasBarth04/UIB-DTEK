// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`iterator-zip-iteration-iterator-step-value-abrupt-completion`, () => {

    var log = [];

    var first = {
      next() {
        log.push("call first next");
        return { done: false };
      },
      return() {
        // Called with the correct receiver and no arguments.
        expect(this).toEqual(first);
        expect(arguments.length).toBe(0);

        // NB: Log after above asserts, because failures aren't propagated.
        log.push("call first return");

        // IteratorClose ignores new exceptions when called with a Throw completion.
        throw new Error();
      }
    };

    var second = {
      next() {
        log.push("call second next");
        return { done: false };
      },
      return() {
        // Called with the correct receiver and no arguments.
        expect(this).toEqual(second);
        expect(arguments.length).toBe(0);

        // NB: Log after above asserts, because failures aren't propagated.
        log.push("call second return");

        throw new Error();
      }
    };

    var third = {
      next() {
        log.push("call third next");
        return { done: false };
      },
      return() {
        // Called with the correct receiver and no arguments.
        expect(this).toEqual(third);
        expect(arguments.length).toBe(0);

        // NB: Log after above asserts, because failures aren't propagated.
        log.push("call third return");

        return {};
      }
    };

    var fourth = {
      next() {
        log.push("call fourth next");
        return { done: true };
      },
      return() {
        log.push("unexpected call fourth return");
      }
    };

    var it = Iterator.zip([first, second, third, fourth], {});

    it.next();

    expect(function () {
      it.return();
    }).not.toThrow();

    expect(log).toEqual([
      "call first next",
      "call second next",
      "call third next",
      "call fourth next",

      "call first return",
      "call second return",
      "call third return",
    ]);
  });
});