// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');
const allowProxyTraps = require('./allowProxyTraps');

class ExpectedError extends Error { }

describe('Iterator.zip', () => {
  test(`iterables-iteration`, () => {

    // Object implementing Iterator protocol, but throws when calling any Iterator methods.
    var throwingIterator = {
      next() {
        throw new ExpectedError();
      },
      return() {
        throw new ExpectedError();
      }
    };

    var iterableReturningThrowingIterator = {
      [Symbol.iterator]() {
        return throwingIterator;
      }
    };

    // "iterables" argument must be an iterable.
    expect(() => {
      Iterator.zip({}).next();
    }).toThrow(TypeError);

    // GetIteratorFlattenable accepts both iterables and iterators.
    // But throws when calling next() in iterables

    expect(() => {
      Iterator.zip([
        throwingIterator,
        iterableReturningThrowingIterator,
      ]).next();
    }).toThrow(ExpectedError);

    // GetIteratorFlattenable rejects non-objects.
    var badIterators = [
      undefined,
      null,
      true,
      "",
      Symbol(),
      0,
      0n,
    ];

    for (var iterator of badIterators) {
      expect(() => {
        Iterator.zip([iterator]).next();
      }).toThrow(TypeError);
    }



    // GetIterator and GetIteratorFlattenable read properties in the correct order.
    var log = [];

    function makeProxyWithGetHandler(name, obj) {
      return new Proxy(obj, allowProxyTraps({
        get(target, propertyKey, receiver) {
          log.push(`${name}::${String(propertyKey)}`);
          return Reflect.get(target, propertyKey, receiver);
        }
      }));
    }

    var elements = [
      // An iterator.
      makeProxyWithGetHandler("first", throwingIterator),

      // An iterable.
      makeProxyWithGetHandler("second", iterableReturningThrowingIterator),

      // An object without any iteration methods.
      makeProxyWithGetHandler("third", {}),
    ];

    var elementsIter = elements.values();

    var iterables = makeProxyWithGetHandler("iterables", {
      [Symbol.iterator]() {
        // Called with the correct receiver and no arguments.
        expect(this).toBe(iterables);
        expect(arguments.length).toBe(0);

        return this;
      },
      next() {
        log.push("call next");

        // Called with the correct receiver and no arguments.
        expect(this).toBe(iterables);
        expect(arguments.length).toBe(0);

        return elementsIter.next();
      },
      return() {
        throw new Error("unexpected call to return method");
      }
    });

    expect(() => Iterator.zip(iterables).next()).toThrow();

    console.log(log);
    expect(log).toEqual([
      "iterables::Symbol(Symbol.iterator)",
      "iterables::next",

      // "call next",
      // "first::Symbol(Symbol.iterator)",
      // "first::next",

      // "call next",
      // "second::Symbol(Symbol.iterator)",

      // "call next",
      // "third::Symbol(Symbol.iterator)",
      // "third::next",

      "call next",
      "iterables::return",
    ]);
  });
});
