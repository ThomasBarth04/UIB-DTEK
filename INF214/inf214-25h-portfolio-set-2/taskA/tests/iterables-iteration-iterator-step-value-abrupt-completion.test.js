// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

class ExpectedError extends Error { }

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

var elements = [first, second];
var elementsIter = elements.values();

var iterables = {
  [Symbol.iterator]() {
    return this;
  },
  next() {
    log.push("call next");
    var result = elementsIter.next();
    if (result.done) {
      throw new ExpectedError();
    }
    return result;
  },
  return() {
    // This method shouldn't be called.
    log.push("UNEXPECTED - close iterables iterator");

    // IteratorClose ignores new exceptions when called with a Throw completion.
    throw new Error();
  },
};

describe('Iterator.zip', () => {
  test(`iterables-iteration-iterator-step-value-abrupt-completion`, () => {


    expect(() => {
      Iterator.zip(iterables).next();
    }).toThrow(ExpectedError);

    // Ensure iterators are closed in the correct order.
    expect(log).toEqual([
      "call next",
      "call next",
      "call next",
      "close first iterator",
      "close second iterator",
    ]);
  });
});