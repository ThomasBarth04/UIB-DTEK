// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

var invalidIterables = [
  undefined,
  null,
  true,
  "",
  Symbol(),
  0,
  0n,
];

describe('Iterator.zip', () => {
  test(`iterables-primitive`, () => {
    // Throws when the "iterables" argument is absent.
    expect(() => {
      Iterator.zip().next();
    }).toThrow(TypeError);

    // Throws a TypeError for invalid iterables values.
    for (var iterables of invalidIterables) {
      expect(() => {
        Iterator.zip(iterables).next();
      }).toThrow(TypeError);
    }

    // Options argument not read when iterables is not an object.
    var badOptions = {
      get mode() {
        throw new Error();
      },
      get padding() {
        throw new Error();
      }
    };
    for (var iterables of invalidIterables) {
      expect(() => {
        Iterator.zip(iterables, badOptions).next();
      }).toThrow(TypeError);
    }
  });
});