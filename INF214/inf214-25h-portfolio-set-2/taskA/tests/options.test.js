// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`options`, () => {

    var validOptions = [
      undefined,
      {},
    ];

    var invalidOptions = [
      null,
      true,
      "",
      Symbol(),
      0,
      0n,
    ];

    // The "options" argument can also be absent.
    Iterator.zip([]).next();

    // All valid option values are accepted.
    for (var options of validOptions) {
      Iterator.zip([], options).next();
    }

    // Throws a TypeError for invalid option values.
    for (var options of invalidOptions) {
      expect(function () {
        Iterator.zip([], options).next();
      }).toThrow(TypeError);
    }
  });
});