// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');
const allowProxyTraps = require('./allowProxyTraps');

describe('Iterator.zip', () => {
  test(`padding-iteration`, () => {

    class Test214Error extends Error { }

    function makeProxyWithGetHandler(log, name, obj) {
      return new Proxy(obj, allowProxyTraps({
        get(target, propertyKey, receiver) {
          log.push(`${name}::${String(propertyKey)}`);
          return Reflect.get(target, propertyKey, receiver);
        }
      }));
    }

    // "padding" option must be an iterable.
    expect(function () {
      Iterator.zip([], {
        padding: {},
      }).next();
    }).toThrow(TypeError);

    for (var n = 0; n <= 5; ++n) {
      var iterables = Array(n).fill([]);

      for (var k = 0; k <= n + 2; ++k) {
        var elements = Array(k).fill(0);
        var elementsIter = elements.values();

        var log = [];

        var padding = makeProxyWithGetHandler(log, "padding", {
          [Symbol.iterator]() {
            log.push("call iterator");

            // Called with the correct receiver and no arguments.
            expect(this).toBe(padding);
            expect(arguments.length).toBe(0);

            return this;
          },
          next() {
            log.push("call next");

            // Called with the correct receiver and no arguments.
            expect(this).toBe(padding);
            expect(arguments.length).toBe(0);

            return elementsIter.next();
          },
          return() {
            log.push("call return");

            // Called with the correct receiver and no arguments.
            expect(this).toBe(padding);
            expect(arguments.length).toBe(0);

            return {};
          }
        });

        Iterator.zip(iterables, { padding }).next();

        // Property reads and calls from GetIterator.
        var expected = [
          "padding::Symbol(Symbol.iterator)",
          "call iterator",
          "padding::next",
        ];

        // Call the "next" method |n| times until the padding iterator is exhausted.
        for (var i = 0; i < Math.min(n, k); ++i) {
          expected.push("call next");
        }

        // If |n| is larger than |k|, then there was one final call to the "next"
        // method. Otherwise the "return" method was called to close the padding
        // iterator.
        if (n > k) {
          expected.push("call next");
        } else {
          expected.push(
            "padding::return",
            "call return"
          );
        }

        expect(log).toEqual(expected);
      }
    }
  });
});