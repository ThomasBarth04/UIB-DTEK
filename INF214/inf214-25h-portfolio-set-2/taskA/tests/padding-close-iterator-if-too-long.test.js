// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`padding-close-iterator-if-too-long.test`, () => {
    function* makeRangeIterator(start = 0, end = Infinity, step = 1) {
      let iterationCount = 0;
      for (let i = start; i < end; i += step) {
        iterationCount++;
        yield i;
      }
      return iterationCount;
    }

    // If the iterables are empty, we still need to close the padding iterator somehow.
    let padding = makeRangeIterator(0, 10);
    Iterator.zip([], { padding }).next();

    expect(padding.next()).toEqual({ value: undefined, done: true });

    padding = makeRangeIterator(0, 10);
    expect(Iterator.zip([[1], [2]], { padding }).next()).toEqual({ "done": false, "value": [1, 2] });

    expect(padding.next()).toEqual({ value: undefined, done: true });
  });
});