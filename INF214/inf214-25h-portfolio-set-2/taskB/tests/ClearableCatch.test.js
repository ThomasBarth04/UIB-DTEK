import ClearablePromise from "../lib/ClearablePromise.js";

describe('ClearableCatch', () => {

  {
    let c_promise_1 = new ClearablePromise(() => "cleared"); //clearing function is then ()=>32
    let c_promise_2 = c_promise_1.then(() => "unexpected resolved 1");
    let c_promise_3 = c_promise_2.catch((x) => x + " caught;")

    setTimeout(() => c_promise_1.reject("rejected;"), 1000);
    setTimeout(() => c_promise_3.clear(), 5000);

    test("promise 1 should be; rejected;", () => {
      expect(c_promise_1._promise).rejects.toBe("rejected;");
      expect(c_promise_1 instanceof ClearablePromise).toBe(true);
    });

    test("promise 2 should be: rejected;", () => {
      expect(c_promise_2._promise).rejects.toBe("rejected;");
      expect(c_promise_2 instanceof ClearablePromise).toBe(true);
    });

    test("promise 3 should be: rejected; caught;", () => {
      expect(c_promise_3._promise).resolves.toBe("rejected; caught;");
      expect(c_promise_3 instanceof ClearablePromise).toBe(true);
    });
  }

  {
    let log = [];

    let r_promise_1 = new ClearablePromise(() => "cleared");
    let r_promise_2 = r_promise_1.then((x) => { log.push(x); return ClearablePromise.reject("reject") });
    let r_promise_3 = r_promise_2.catch((x) => { log.push(x); return "rejection caught" })
    let r_promise_4 = r_promise_3.then((x) => { log.push(x); return "chain restored" })
    let r_promise_5 = r_promise_4.then((x) => log.push(x))

    setTimeout(() => r_promise_1.resolve("resolved"), 1000);
    setTimeout(() => r_promise_3.clear(), 5000);

    test("promise_1 should be: resolved", () => {
      expect(r_promise_1 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_1).resolves.toBe("resolved");
    });
    test("promise_2 should be: reject", () => {
      expect(r_promise_2 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_2).rejects.toBe("reject");
    });
    test("promise_3 should be: rejection caught", () => {
      expect(r_promise_3 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_3).resolves.toBe("rejection caught");
    });
    test("promise_4 should be: chain restored", () => {
      expect(r_promise_4 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_4).resolves.toBe("chain restored");
    });
    test("promise_5 should be: 4", () => {
      expect(r_promise_5 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_5).resolves.toBe(4);
    });

    test('log should be ["resolved","reject", "rejection caught", "chain restored"]', () => {
      return expect(log).toEqual(["resolved", "reject", "rejection caught", "chain restored"]);
    });
  }

  {
    let log = [];

    let r_promise_1 = new ClearablePromise(() => "cleared");
    let r_promise_2 = r_promise_1.then((x) => { log.push(x); return ClearablePromise.reject(Error("reject")); });
    let r_promise_3 = r_promise_2.catch((x) => { log.push(x.message); return "rejection caught" })
    let r_promise_4 = r_promise_3.then((x) => { log.push(x); return "chain restored" })
    let r_promise_5 = r_promise_4.then((x) => log.push(x))

    setTimeout(() => r_promise_1.resolve("resolved"), 1000);
    setTimeout(() => r_promise_3.clear(), 5000);

    test("promise_1 should be: resolved", () => {
      expect(r_promise_1 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_1).resolves.toBe("resolved");
    });
    test("promise_2 should be: reject", () => {
      expect(r_promise_2 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_2).rejects.toThrow(Error("reject"));
    });
    test("promise_3 should be: rejection caught", () => {
      expect(r_promise_3 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_3).resolves.toBe("rejection caught");
    });
    test("promise_4 should be: chain restored", () => {
      expect(r_promise_4 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_4).resolves.toBe("chain restored");
    });
    test("promise_5 should be: 4", () => {
      expect(r_promise_5 instanceof ClearablePromise).toBe(true);
      return expect(r_promise_5).resolves.toBe(4);
    });

    test('log should be ["resolved","reject", "rejection caught", "chain restored"]', () => {
      return expect(log).toEqual(["resolved", "reject", "rejection caught", "chain restored"]);
    });
  }

  {
    let r_promise_1 = new ClearablePromise(() => "cleared;");
    let r_promise_2 = r_promise_1.then((x) => x + " chain 1;")
    let r_promise_3 = r_promise_2.catch((x) => x + " unexpected use of catch")
    let r_promise_4 = r_promise_3.then((x) => x + " chain 2;")

    setTimeout(() => r_promise_1.reject("rejected"), 5000);
    setTimeout(() => r_promise_3.clear(), 1000);

    test("promise_1 should be: cleared", () => {
      return expect(r_promise_1).resolves.toBe("cleared;");
    });
    test("promise_2 should be: reject", () => {
      return expect(r_promise_2).resolves.toBe("cleared; chain 1;");
    });
    test("promise_3 should be: rejection caught", () => {
      return expect(r_promise_3).resolves.toBe("cleared; chain 1;");
    });
    test("promise_4 should be: chain restored", () => {
      return expect(r_promise_4).resolves.toBe("cleared; chain 1; chain 2;");
    });
  }
});