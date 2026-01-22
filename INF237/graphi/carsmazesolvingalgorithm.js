const fs = require("fs");
const input = fs.readFileSync(0, "utf8").trim().split('\n');

const [rows, cols] = input.shift().split(" ").map(Number);

const [start_x, start_y] = input.shift().split(" ").map(Number).map(x => x - 1);
const [end_x, end_y] = input.shift().split(" ").map(Number).map(x => x - 1);

const map2d = input.map(l => l.split(''));

const queue = [[start_x, start_y, 3]];
const visited = new Set();

const directions = [
  [0, 1],   // right (index 0)
  [-1, 0],  // up    (index 1)
  [0, -1],  // left  (index 2)
  [1, 0],   // down  (index 3)
];

let yes = false;

let [x, y, dir] = [start_x, start_y, 0];
outer:
while (true) {
  if (x === end_x && y === end_y) {
    console.log("1");
    yes = true;
    break outer;
  }

  const currentKey = `${x},${y},${dir}`;
  //loop
  if (visited.has(currentKey)) {
    break outer;
  }
  visited.add(currentKey);

  //left
  const rotate_left = (dir + 1) % 4;
  let [shift_x, shift_y] = [x + directions[rotate_left][0], y + directions[rotate_left][1]];

  if (
    shift_x >= 0 && shift_x < rows &&
    shift_y >= 0 && shift_y < cols &&
    map2d[shift_x][shift_y] == "0"
  ) {
    x = shift_x;
    y = shift_y;
    dir = rotate_left;
    continue;
  }

  //rett fram
  [shift_x, shift_y] = [x + directions[dir][0], y + directions[dir][1]];

  if (
    shift_x >= 0 && shift_x < rows &&
    shift_y >= 0 && shift_y < cols &&
    map2d[shift_x][shift_y] == "0"
  ) {
    x = shift_x;
    y = shift_y;
    continue;
  }

  // right, stille
  const rotate_right = (dir - 1 + 4) % 4;
  dir = rotate_right;
}

if (!yes) {
  console.log("0");
}

