import ClearablePromise from "../lib/ClearablePromise.js";

class Test214Error extends Error { }

describe('ClearableThen', () => {

  {
    let f_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
    let f_promise_2 = f_promise_1.then((x) => x * 2);
    let f_promise_3 = f_promise_2.then((x) => x + 10);

    setTimeout(() => f_promise_1.resolve(16), 5000);
    setTimeout(() => f_promise_3.clear(), 1000);

    test("promise 1 should be 32: ", () => {
      expect(f_promise_1._promise).resolves.toBe(32);
    });

    test("promise 2 should be 64: ", () => {
      expect(f_promise_2._promise).resolves.toBe(64);
    });

    test("promise 3 should be 74: ", () => {
      expect(f_promise_3._promise).resolves.toBe(74);
    });
  }

  {
    let f_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
    let f_promise_2 = f_promise_1.then((x) => x * 2);
    let f_promise_3 = f_promise_2.then((x) => x + 10);

    setTimeout(() => f_promise_1.resolve(16), 1000);
    setTimeout(() => f_promise_3.clear(), 5000);

    test("promise 1 should be 16: ", () => {
      expect(f_promise_1._promise).resolves.toBe(16);
    });

    test("promise 2 should be 32: ", () => {
      expect(f_promise_2._promise).resolves.toBe(32);
    });

    test("promise 3 should be 42: ", () => {
      expect(f_promise_3._promise).resolves.toBe(42);
    });
  }

  {
    let f_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
    let f_promise_2 = f_promise_1.then((x) => x * 2, (x) => x * 3);
    let f_promise_3 = f_promise_2.then((x) => x + 10, (x) => x - 10);

    setTimeout(() => f_promise_1.reject(16), 1000);
    setTimeout(() => f_promise_3.clear(), 5000);

    test("promise 1 should be 16: ", () => {
      expect(f_promise_1._promise).rejects.toBe(16);
    });

    test("promise 2 should be 48: ", () => {
      expect(f_promise_2._promise).resolves.toBe(48);
    });

    test("promise 3 should be 58: ", () => {
      expect(f_promise_3._promise).resolves.toBe(58);
    });
  }

  {
    let f_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
    let f_promise_2 = f_promise_1.then((x) => x * 2);
    let f_promise_3 = f_promise_2.then((x) => x + 10);

    setTimeout(() => f_promise_1.reject(new Test214Error()), 1000);
    setTimeout(() => f_promise_3.clear(), 5000);

    test("promise 1 should throw", () => {
      expect(f_promise_1._promise).rejects.toThrow(Test214Error);
    });

    test("promise 2 should propagate error", () => {
      expect(f_promise_2._promise).rejects.toThrow(Test214Error);
    });

    test("promise 3 should propagate error", () => {
      expect(f_promise_3._promise).rejects.toThrow(Test214Error);
    });
  }

  {
    let f_promise_1 = new ClearablePromise(() => "unexpected clear;"); //clearing function is then ()=>32
    let f_promise_2 = f_promise_1.then((x) => x + " unexpected resolve;");
    let f_promise_3 = f_promise_2.then((x) => x + " unexpected resolve;", (x) => "caught rejection");

    setTimeout(() => f_promise_1.reject(new Test214Error()), 1000);
    setTimeout(() => f_promise_3.clear(), 5000);

    test("promise 1 should throw", () => {
      expect(f_promise_1._promise).rejects.toThrow(Test214Error);
    });

    test("promise 2 should propagate error", () => {
      expect(f_promise_2._promise).rejects.toThrow(Test214Error);
    });

    test("promise 3 should catch the error", () => {
      expect(f_promise_3._promise).resolves.toBe("caught rejection");
    });
  }

  {
    let promise_1 = new ClearablePromise(() => "clearing;");
    let promise_2 = promise_1.then(
      (x) => x + " chain 1;",
      (e) => "error"
    );
    let promise_3 = promise_2.then((x) => x + " chain 2;");
    setTimeout(() => promise_1.resolve("resolving"), 3000);
    setTimeout(() => promise_3.clear(), 1000);

    test("promise_1 should be clearing;", () => {
      return expect(promise_1).resolves.toBe("clearing;");
    });
    test("promise_2 should be clearing; chain 1;", () => {
      return expect(promise_2).resolves.toBe("clearing; chain 1;");
    });
    test("promise_3 should be clearing; chain 1; chain 2;", () => {
      return expect(promise_3).resolves.toBe("clearing; chain 1; chain 2;");
    });
  }

  {
    let r_promise_1 = new ClearablePromise(() => "clearing;");
    let r_promise_2 = r_promise_1.then((x) => x + " chain 1;");
    let r_promise_3 = r_promise_2.then((x) => x + " chain 2;");

    setTimeout(() => r_promise_1.reject("rejecting;"), 1000);
    setTimeout(() => r_promise_3.clear(), 5000);

    test("promise_1 should be rejecting;", () => {
      return expect(r_promise_1).rejects.toBe("rejecting;");
    });
    test("promise_2 should be rejecting;", () => {
      return expect(r_promise_2).rejects.toBe("rejecting;");
    });
    test("promise_3 should be rejecting;", () => {
      return expect(r_promise_3).rejects.toBe("rejecting;");
    });
  }
});