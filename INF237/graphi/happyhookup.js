const fs = require('fs');

const input = fs.readFileSync(0, 'utf-8')
const lines = input.trim().split('\n')
const n = parseInt(lines[0].split(" ")[1])
const tree = new Map();

for (let i = 1; i <= n; i++) {
  const [a, b] = lines[i].split(' ').map(Number);
  if (!tree.has(a)) tree.set(a, []);
  tree.get(a).push(b);
}

const [start_a, start_b] = lines.at(-1).split(" ").map(Number);
const reachable_from_a = new Set([start_a]);
const reachable_from_b = new Set([start_b]);

const queue_a = [start_a];
const queue_b = [start_b];
head_a = 0;
head_b = 0;
const visited_a = new Set();
const visited_b = new Set();

let yes = false;

outer:
while (head_a < queue_a.length || head_b < queue_b.length) {
  if (head_a < queue_a.length) {
    const a = queue_a[head_a++]
    visited_a.add(a);
    for (let val of tree.get(a) ?? []) {
      if (reachable_from_b.has(val)) {
        console.log("yes\n" + val);
        yes = true;
        break outer;
      }

      if (!visited_a.has(val)) {
        queue_a.push(val);
        reachable_from_a.add(val)

      }

    }
  }

  if (head_b < queue_b.length) {
    const b = queue_b[head_b++]
    visited_b.add(b);
    for (let val of tree.get(b) ?? []) {
      if (reachable_from_a.has(val)) {
        console.log("yes\n" + val);
        yes = true;
        break outer;
      }
      if (!visited_b.has(val)) {
        queue_b.push(val);
        reachable_from_b.add(val)
      }
    }
  }
}
if (!yes) { console.log("no") };
