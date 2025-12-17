import ClearablePromise from "../lib/ClearablePromise.js";

describe('ClearableFinally', () => {

  {
    let log = [];

    let c_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
    let c_promise_2 = c_promise_1.then((x) => x * 2);
    let c_promise_3 = c_promise_2.then((x) => x + 10);
    let f_promise_1 = c_promise_1.finally(() => log.push("Promise " + 1));
    let f_promise_2 = c_promise_2.finally(() => log.push("Promise " + 2));
    let f_promise_3 = c_promise_3.finally(() => log.push("Promise " + 3));

    setTimeout(() => c_promise_1.resolve(16), 5000);
    setTimeout(() => c_promise_3.clear(), 1000);

    test("promise 1 should be 32: ", () => {
      return expect(c_promise_1._promise).resolves.toBe(32);
    });

    test("promise 2 should be 64: ", () => {
      return expect(c_promise_2._promise).resolves.toBe(64);
    });

    test("promise 3 should be 74: ", () => {
      return expect(c_promise_3._promise).resolves.toBe(74);
    });

    test("f_promise_1 should be same as promise 1: ", () => {
      expect(f_promise_1._promise).resolves.toBe(32);
    });

    test("f_promise_2 should be same as promise 2: ", () => {
      expect(f_promise_2._promise).resolves.toBe(64);
    });

    test("f_promise_3 should be same as promise 3: ", () => {
      expect(f_promise_3._promise).resolves.toBe(74);
    });

    test("log should be filled in correct order: ", () => {
      expect(log).toEqual(["Promise 1", "Promise 2", "Promise 3"]);
    });
  }

  {
    let log = [];

    let c_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
    let c_promise_2 = c_promise_1.then((x) => x * 2);
    let c_promise_3 = c_promise_2.then((x) => x + 10);
    let f_promise_1 = c_promise_1.finally(() => log.push("Promise " + 1));
    let f_promise_3 = c_promise_3.finally(() => log.push("Promise " + 3));

    setTimeout(() => c_promise_1.resolve(16), 5000);
    setTimeout(() => c_promise_3.clear(), 1000);

    test("promise 1 should be 32: ", () => {
      return expect(c_promise_1._promise).resolves.toBe(32);
    });

    test("promise 2 should be 64: ", () => {
      return expect(c_promise_2._promise).resolves.toBe(64);
    });

    test("promise 3 should be 74: ", () => {
      return expect(c_promise_3._promise).resolves.toBe(74);
    });

    test("f_promise_1 should be same as promise 1: ", () => {
      expect(f_promise_1._promise).resolves.toBe(32);
    });

    test("f_promise_3 should be same as promise 3: ", () => {
      expect(f_promise_3._promise).resolves.toBe(74);
    });

    test("log should be filled in correct order: ", () => {
      expect(log).toEqual(["Promise 1", "Promise 3"]);
    });
  }
});