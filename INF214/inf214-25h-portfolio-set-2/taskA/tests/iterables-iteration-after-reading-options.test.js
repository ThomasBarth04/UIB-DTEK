// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`iterables-iteration-after-reading-options`, () => {
    var log = [];

    var iterables = {
      [Symbol.iterator]() {
        log.push("get iterator");
        return this;
      },
      next() {
        return { done: true };
      }
    };

    var options = {
      get padding() {
        log.push("get padding");
        return [];
      }
    };

    Iterator.zip(iterables, options).next();

    expect(log).toEqual([
      "get padding",
      "get iterator",
    ]);
  });
});