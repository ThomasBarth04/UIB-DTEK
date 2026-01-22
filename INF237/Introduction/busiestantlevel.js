const fs = require('fs');

const input = fs.readFileSync(0, 'utf-8')
const lines = input.trim().split('\n')
const n = parseInt(lines[0])
const tree = new Map();

for (let i = 1; i < n; i++) {
  const [a, b] = lines[i].split(' ').map(Number);
  if (!tree.has(a)) tree.set(a, []);
  if (!tree.has(b)) tree.set(b, []);

  tree.get(a).push(b);
  tree.get(b).push(a);
}

const levelMap = new Map();
let start = 0;
levelMap.set(start, 0)

//bfs
const queue = [[0, 0]];
let head = 0;
const visited = new Uint8Array(n);
visited[0] = 1;
const levelCount = [];

while (head < queue.length) {
  const [node, level] = queue[head++]
  levelCount[level] = (levelCount[level] ?? 0) + 1

  for (const n of tree.get(node) ?? []) {
    if (!visited[n]) {
      visited[n] = 1;
      queue.push([n, level + 1])
    }
  }
}

//fin level med mest
let maxCount = -1;
let bestLevel = 0;

for (let level = 0; level < levelCount.length; level++) {
  if (levelCount[level] > maxCount) {
    maxCount = levelCount[level];
    bestLevel = level;
  }
}

console.log(bestLevel)

