const fs = require("fs");
const input = fs.readFileSync(0, "utf8").trim().split('\n');


//fjerner første rad fra input
const [rows, cols] = input.shift().split(" ").map(Number);

const map2d = input.map(l => l.split(''));

const directions = [
  [1, 0],   // down
  [-1, 0],  // up
  [0, 1],   // right
  [0, -1]   // left
];

const drivable = [".", "S", "C", "P"];

let depos = [];
for (let i = 0; i < rows; i++) {
  for (let j = 0; j < cols; j++) {
    if (map2d[i][j] == "S") {
      depos.push([i, j]);
    }
  }
}

let count = 0;
for (let depo of depos) {
  const queue = [depo];
  map2d[depo[0]][depo[1]]

  while (queue.length) {
    const [x, y] = queue.shift();

    for (const [shift_r, shift_c] of directions) {
      const shift_x = x + shift_r;
      const shift_y = y + shift_c;

      if (
        shift_x >= 0 && shift_x < rows &&
        shift_y >= 0 && shift_y < cols
      ) {
        if (drivable.includes(map2d[shift_x][shift_y])) {
          if (map2d[shift_x][shift_y] == "P") { count++ };
          map2d[shift_x][shift_y] = "V"
          queue.push([shift_x, shift_y]);
        }
      }
    }
  }

}

console.log(count);


