// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

class ExpectedError extends Error { }

var badIterators = [
  // Throw TypeError in GetIteratorFlattenable because strings are rejected.
  {
    iterator: "bad iterator",
    error: TypeError
  },

  // Throw an error when GetIteratorFlattenable performs GetMethod.
  {
    iterator: {
      get [Symbol.iterator]() {
        throw new ExpectedError();
      }
    },
    error: ExpectedError,
  },

  // Throw an error when GetIteratorFlattenable performs Call.
  {
    iterator: {
      [Symbol.iterator]() {
        throw new ExpectedError();
      }
    },
    error: ExpectedError,
  },

  // // Throw an error when GetIteratorFlattenable performs GetIteratorDirect.
  // {
  //   iterator: {
  //     get next() {
  //       throw new ExpectedError();
  //     }
  //   },
  //   error: ExpectedError,
  // },
];

function makeIterables(badIterator) {
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
      log.push("close first iterator");

      // IteratorClose ignores new exceptions when called with a Throw completion.
      throw new Error();
    },
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
      log.push("close second iterator");

      // IteratorClose ignores new exceptions when called with a Throw completion.
      throw new Error();
    },
  };

  var elements = [first, second, badIterator];
  var elementsIter = elements.values();

  var iterables = {
    [Symbol.iterator]() {
      return this;
    },
    next() {
      log.push("call next");
      return elementsIter.next();
    },
    return() {
      log.push("close iterables iterator");

      // IteratorClose ignores new exceptions when called with a Throw completion.
      throw new Error();
    },
  };

  return { log, iterables };
}

describe('Iterator.zip', () => {
  test(`iterables-iteration-get-iterator-flattenable-abrupt-completion`, () => {
    for (var { iterator, error } of badIterators) {
      var { log, iterables } = makeIterables(iterator);

      expect(() => {
        Iterator.zip(iterables).next();
      }).toThrow(error);

      // Ensure iterators are closed in the correct order.
      console.log(log);
      expect(log).toEqual([
        "call next",
        "call next",
        "call next",
        "close iterables iterator",
        "close first iterator",
        "close second iterator",
      ]);
    }
  });
});
