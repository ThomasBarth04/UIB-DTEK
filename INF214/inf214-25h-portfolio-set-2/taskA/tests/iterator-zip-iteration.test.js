// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`iterator-zip-iteration-iterator-step-value-abrupt-completion`, () => {

    function makeIterator(log, name, elements) {
      var elementsIter = elements.values();
      var iterator = {
        next() {
          log.push(`call ${name} next`);

          // Called with the correct receiver and no arguments.
          expect(this).toEqual(iterator);
          expect(arguments.length).toBe(0);

          var result = elementsIter.next();
          return {
            get done() {
              log.push(`get ${name}.result.done`);
              return result.done;
            },
            get value() {
              log.push(`get ${name}.result.value`);
              return result.value;
            },
          };
        },
        return() {
          log.push(`call ${name} return`);

          // Called with the correct receiver and no arguments.
          expect(this).toEqual(iterator);
          expect(arguments.length).toBe(0);

          return {
            get done() {
              log.push(`unexpected get ${name}.result.done`);
              return result.done;
            },
            get value() {
              log.push(`unexpected get ${name}.result.value`);
              return result.value;
            },
          };
        }
      };
      return iterator;
    }

    var log = [];
    var iterables = [
      makeIterator(log, "first", [1, 2, 3]),
      makeIterator(log, "second", [4, 5, 6]),
      makeIterator(log, "third", [7, 8, 9]),
    ];
    var it = Iterator.zip(iterables, {});

    log.push("start");
    for (var v of it) {
      log.push("loop");
    }

    var expected = [
      "start",

      "call first next",
      "get first.result.done",
      "get first.result.value",
      "call second next",
      "get second.result.done",
      "get second.result.value",
      "call third next",
      "get third.result.done",
      "get third.result.value",
      "loop",

      "call first next",
      "get first.result.done",
      "get first.result.value",
      "call second next",
      "get second.result.done",
      "get second.result.value",
      "call third next",
      "get third.result.done",
      "get third.result.value",
      "loop",

      "call first next",
      "get first.result.done",
      "get first.result.value",
      "call second next",
      "get second.result.done",
      "get second.result.value",
      "call third next",
      "get third.result.done",
      "get third.result.value",
      "loop",

      "call first next",
      "get first.result.done",
      "call second next",
      "get second.result.done",
      "call third next",
      "get third.result.done",
    ];

    expect(log).toEqual(expected);
  });
});