const { log } = require("console"); const fs = require("fs");
const input = fs.readFileSync(0, "utf8").trim().split('\n');


//fjerner første rad fra input
const [rows, cols] = input.shift().split(" ").map(Number);
const graph = new Map();

const map2d = input.map(l => l.split(''));

const directions = [
  [1, 0],   // down
  [-1, 0],  // up
  [0, 1],   // right
  [0, -1]   // left
];

const blocked = ["W", "#"];
const drivable = [".", "S", "C", "P"];

class Node {
  constructor(symbol, x, y) {
    this.symbol = symbol;
    this.x = x;
    this.y = y;
  }
}


const start = [0, 0];
const queue = [start];
let count = 0;

while (queue.length) {
  const [x, y] = queue.pop();
  if (map2d[x][y] == "P") { count++ };
  map2d[x][y] = "V";
  for (const [shift_r, shift_c] of directions) {
    const shift_x = x + shift_r;
    const shift_y = y + shift_c;

    if (
      shift_x >= 0 && shift_x < rows &&
      shift_x >= 0 && shift_c < cols
    ) {
      if (drivable.includes(map2d[shift_x][shift_y])) {
        queue.push([shift_x, shift_y]);
      }
    }
  }
}
console.log(count);

//create graph
for (let i = 0; i < rows; i++) {
  for (let j = 0; j < cols; j++) {
    const node = new Node(map2d[i][j], i, j);
    if (blocked.includes(node.symbol)) {
      continue;
    }
    graph.set(node, []);
    for (const [shift_r, shift_c] of directions) {
      const shift_i = i + shift_r;
      const shift_j = j + shift_c;

      if (
        shift_i >= 0 && shift_i < rows &&
        shift_j >= 0 && shift_j < cols
      ) {
        shift_node = new Node(map2d[shift_i][shift_j], shift_i, shift_j);
        if (drivable.includes(shift_node.symbol)) {
          graph.get(node).push(shift_node);
        }

      }


    }

  }
}







