export default class ClearablePromise {
  /**
   * @param onClear: Function returning the value the promise should resolve with when ``clear`` is called
   */
  constructor(onClear) {
    let { promise, resolve, reject } = Promise.withResolvers();
    [this._promise, this.resolve, this.reject] = [promise, resolve, reject];
    if (onClear) {
      this._fetchValue = onClear;
    }
  }
  get promise() {
    return this._promise;
  }

  /**
   * Method to chain a promise with fulfill- and reject-reactions.
   *
   * @param onFulfilled: The function called when the promise ``then`` is called on gets resolved. Returns the value the new promise gets resolved with.
   * @param onRejected: An optional function to handle rejections. The function called when the promise ``then`` is called on is rejected. Returns the value the new promise gets rejected with.
   * @returns a new promise dependent on the promise ``then``was called on
   */
  then(onFulfilled, onRejected) {
    let newPromise = new ClearablePromise();
    newPromise._setSourcePromise(this);
    this._promise.then(
      (x) => {
        const fulfilledVal = typeof onFulfilled === "function" ? onFulfilled(x) : x;
        if (fulfilledVal instanceof ClearablePromise) {
          newPromise._setSourcePromises([fulfilledVal]);
          fulfilledVal.then(
            (v) => newPromise.resolve(v),
            (e) => newPromise.reject(e)
          );
        } else {
          newPromise.resolve(fulfilledVal);
        }
      },
      (y) => {
        if (typeof onRejected === "function") {
          const rejectedVal = onRejected(y);
          if (onRejected instanceof ClearablePromise) {
            newPromise._setSourcePromises([rejectedVal]);
            rejectedVal.then(
              (v) => newPromise.resolve(v),
              (e) => newPromise.rejcet(e)
            );
            // TODO!
          } else {
            newPromise.resolve(rejectedVal);
          }
        } else {
          newPromise.reject(y)
        }
      }
    );
    return newPromise;
  }

  /**
   * Method used to "catch" an error, normally at the end of a promise chain
   *
   * @param onRejected the function to handle a value sent from a rejected promise
   * @returns a new pending promise
   */
  catch(onRejected) {
    return this.then(undefined, onRejected);
  }

  // TODO: Complete the implementation of this function.
  /**
   * Method to schedule a function to be called when a promise is settled
   *
   * @param onFinally: A function executed when the promise settles
   * @returns a new pending promise, to be settled with the same value as the current promise
   */
  finally(onFinally) {
    if (typeof onFinally != "function") {
      return this.then(onFinally, onFinally);
    } else {
      return this.then(
        (value) => ClearablePromise.resolve(onFinally()).then(() => value),
        (reason) =>
          ClearablePromise.resolve(onFinally()).then(() => {
            throw reason;
          })
      );
    }
  }

  /**
   * Method to clear promise chain, will resolve promise with ``onClear`` function, or call itself recursively on the source promise.
   * If this._fetchValue is undefined, this function should call itself recursively on all source promises (if there is a source promise). 
   */
  clear() {
    if (typeof this._fetchValue === "function") {
      try {
        const v = this._fetchValue();
        this.resolve(v);
      } catch (e) {
        this.reject(e)
      }
    } else if (this._sourcePromise && this._sourcePromise.length) {
      this._sourcePromise.forEach((sp) => {
        if (sp && typeof sp.clear === "function") sp.clear();
      })
    }
  }

  /**
   * Method to set source promise(s) of new promise.
   *
   * @param sourcePromise: The preceding promise in a promise chain
   */
  _setSourcePromise(sourcePromise) {
    this._sourcePromise = [sourcePromise];
  }

  /**
   * Method to add new source promises to existing source promises.
   *
   * @param sourcePromise
   */
  _setSourcePromises(sourcePromise) {
    if (!this._sourcePromise) {
      this._sourcePromise = sourcePromise;
    } else {
      this._sourcePromise = this._sourcePromise.concat(sourcePromise);
    }
  }

  /**
   * Method to resolve a promise with the values of several promises once they are resolved.
   *
   * @param promiseList: A list of clearable promises.
   * @returns a new promise either resolved with a list of the promiseList's resolved values, or a promise rejected with the first promise of promiseList that got rejected.
   */
  static all(promiseList) {
    let counter = promiseList.length;
    let arr = new Array(counter);
    let promise = new ClearablePromise();

    promise._setSourcePromises(promiseList);

    if (counter === 0) {
      promise.resolve([]);
      return promise;
    }

    for (let i = 0; i < counter; i++) {
      const p = promiseList[i];
      p.then(
        (v) => {
          arr[i] = v;
          counter--;
          if (counter === 0) {
            promise.resolve(arr);
          }
        },
        (e) => {
          promise.reject(e);
        }
      );
    }
    return promise;
  }
  /**
   * Method to create a promise settled with the value of the first promise of a list of promises to settle.
   *
   * @param promiseList: A list of clearable promises.
   * @returns a promise settled with the value of the first promise to settle.
   */
  static race(promiseList) {
    let promise = new ClearablePromise();
    promise._setSourcePromises(promiseList);
    promiseList.forEach((p) =>
      p.then(
        (v) => promise.resolve(v),
        (e) => promise.reject(e)
      )
    );
    return promise;
  }


  /**
   * Method to create a promise fulfilled with the value of the first promise of a list of promises to get resolved.
   *
   * @param promiseList: A list of clearable promises.
   * @returns a promise either resolved with the value of the first promise to resolve, or rejected with a list of values from the rejected promises.
   *          using AggregateError
   */
  static any(promiseList) {
    let promise = new ClearablePromise();
    let rejects = [];
    let remaining = promiseList.length;

    promise._setSourcePromises(promiseList);

    if (remaining === 0) {
      promise.reject(new AggregateError([], "All promises were rejected"));
      return promise;
    }

    promiseList.forEach((p) =>
      p.then(
        (v) => promise.resolve(v),
        (e) => {
          rejects.push(e);
          remaining--;
          if (remaining === 0) {
            promise.reject(new AggregateError(rejects, "All promises were rejected"));
          }
        }
      )
    );
    return promise;
  }  /**
   * Method to create a new resolved promise.
   *
   * @param value to resolve the new promise with.
   * @returns a promise resolved with the value, or if value is a clearable promise, we return the value.
   */
  static resolve(value) {
    if (value instanceof ClearablePromise) {
      return value;
    }
    let promise = new ClearablePromise();
    promise.resolve(value);
    return promise;
  }

  /**
   * Method to create a new rejected promise.
   *
   * @param value to reject the new promise with.
   * @returns a promise rejected with the value passed as an argument.
   */
  static reject(value) {
    let promise = new ClearablePromise();
    promise.reject(value);
    return promise;
  }
}
