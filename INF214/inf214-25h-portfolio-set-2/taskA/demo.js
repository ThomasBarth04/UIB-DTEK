
const Iterator = require('./iteratorZip.js');

console.log("Demo 1:");
// [ [ 0, 3 ], [ 1, 4 ], [ 2, 5 ] ]
console.log(Array.from(Iterator.zip([[0, 1, 2], [3, 4, 5]])));

console.log("\nDemo 2:");
let it1 = Iterator.zip([[0, 1, 2], [3, 4, 5]]);
// { value: [ 0, 3 ], done: false }
console.log(it1.next());
// { value: [ 1, 4 ], done: false }
console.log(it1.next());
// { value: [ 2, 5 ], done: false }
console.log(it1.next());
//{ value: undefined, done: true }
console.log(it1.next());

console.log("\nDemo 3:");
let padding = [100, 101, 102];
let it2 = Iterator.zip([[0, 1], [3, 4, 5], [6, 7, 8, 9]], { padding });
// { value: [ 0, 3, 6 ], done: false }
console.log(it2.next());
// { value: [ 1, 4, 7 ], done: false }
console.log(it2.next());
// { value: [ 100, 5, 8 ], done: false }
console.log(it2.next());
// { value: [ 100, 101, 9 ], done: false }
console.log(it2.next());
//{ value: undefined, done: true }
console.log(it2.next());

console.log("\nDemo 4:");
padding = [100];
let it3 = Iterator.zip([[0, 1], [3, 4, 5], [6, 7, 8, 9]], { padding });
// { value: [ 0, 3, 6 ], done: false }
console.log(it3.next());
// { value: [ 1, 4, 7 ], done: false }
console.log(it3.next());
// { value: [ 100, 5, 8 ], done: false }
console.log(it3.next());
// { value: [ 100, undefined, 9 ], done: false }
console.log(it3.next());
//{ value: undefined, done: true }
console.log(it3.next());