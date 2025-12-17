// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`options-padding`, () => {

    var validPadding = [
      undefined,
      [],
    ];

    var invalidPadding = [
      null,
      false,
      "",
      Symbol(),
      123,
      123n,
    ];

    // Absent "padding" option.
    expect(() =>
      Array.from(Iterator.zip([], {}))).not.toThrow();

    // All valid padding values are accepted.
    for (var padding of validPadding) {
      expect(() =>
        Array.from(Iterator.zip([], { padding }))).not.toThrow();
    }

    // Throws a TypeError for invalid padding options.
    for (var padding of invalidPadding) {
      expect(() => {
        Array.from(Iterator.zip([], { padding }));
      }).toThrow(TypeError);
    }
  });
});