const fs = require('fs');

const input = fs.readFileSync(0, 'utf-8').trim();
const lines = input.split('\n');

const [rows, cols] = lines[0].split(" ").map(Number);
const luckyNr = parseInt(lines[1]);

const grid = lines
  .slice(2)
  .map(row => row.split(" ").map(Number));

let count = 0;

for (let i = 0; i < rows; i++) {
  for (let j = 0; j < cols; j++) {
    if (grid[i][j] === luckyNr) {
      if (checkIfLucky(i, j)) {
        count++
      }
    }
  }
}

console.log(count);

function checkIfLucky(i, j) {
  if (i <= 0 || i >= rows - 1 || j <= 0 || j >= cols - 1) {
    return false;
  }

  let sum =
    grid[i - 1][j - 1] +
    grid[i - 1][j + 1] +
    grid[i + 1][j - 1] +
    grid[i + 1][j + 1];

  if (sum % luckyNr == 0) {
    return true
  }
}
