// =============================================================
// CARL'S MAZE-SOLVING ALGORITHM — Left-Hand Rule (Wall Following)
// =============================================================
//
// PROBLEM: Given a 2D grid maze, determine if Carl's specific algorithm
//          reaches the exit (end_x, end_y) from (start_x, start_y).
//          Output "1" if he reaches the exit, "0" if he gets stuck in a loop.
//
// CARL'S ALGORITHM (Left-Hand Rule):
//   Carl always tries to move in this priority order:
//     1. Turn LEFT and step forward (if that cell is open)
//     2. Go STRAIGHT (if that cell is open)
//     3. Turn RIGHT in place (don't move — just rotate)
//
//   This is the classic "left-hand rule" / "left-wall following" strategy.
//   It works to escape simply-connected mazes (no isolated walls), but
//   can loop forever in mazes with disconnected wall islands.
//
// LOOP DETECTION:
//   State = (x, y, direction). If Carl revisits the same (x, y, dir) triple
//   → he is in an infinite loop → output "0".
//   A visited Set of stringified states detects this in O(1) per step.
//
// DIRECTION ENCODING:
//   Index:  0=right, 1=up, 2=left, 3=down
//   directions[i] = [row_delta, col_delta]
//
//   Turn left  = (dir + 1) % 4   (CCW: right→up→left→down→right)
//   Turn right = (dir - 1 + 4) % 4  (CW: right→down→left→up→right)
//
// DIAGRAM (Carl starts facing right, dir=0):
//
//   Grid ('0' = open, anything else = wall):
//   . . # .
//   . . 0 .    ← Carl starts at (row=1, col=2) facing right (dir=0)
//   . . . .
//
//   Step 1: Try left (dir+1=1=up): cell (0,2) = '#' → blocked
//           Try straight (dir=0=right): cell (1,3) = '.' → MOVE → (1,3), dir=0
//   Step 2: Try left (up): (0,3) = '.' → MOVE → (0,3), dir=1
//   ...
//
// INPUT FORMAT:
//   Line 1: "rows cols"
//   Line 2: "start_x start_y"  (1-indexed → converted to 0-indexed)
//   Line 3: "end_x end_y"      (1-indexed → converted to 0-indexed)
//   Remaining lines: grid rows, each char '0' (open) or other (wall)
//
// TIME:  O(rows × cols × 4) — at most 4 states per cell before loop detected
// SPACE: O(rows × cols × 4) — visited set
// =============================================================

const fs = require("fs");
const input = fs.readFileSync(0, "utf8").trim().split('\n');

// Parse dimensions
const [rows, cols] = input.shift().split(" ").map(Number);

// Parse start and end positions (1-indexed in input → subtract 1 for 0-indexed)
const [start_x, start_y] = input.shift().split(" ").map(Number).map(x => x - 1);
const [end_x, end_y]     = input.shift().split(" ").map(Number).map(x => x - 1);

// Parse the grid: each cell is a character ('0' = passable, anything else = wall)
const map2d = input.map(l => l.split(''));

// Direction vectors: index maps to [row_delta, col_delta]
//   0=right, 1=up, 2=left, 3=down
const directions = [
  [0, 1],   // right (index 0)
  [-1, 0],  // up    (index 1)
  [0, -1],  // left  (index 2)
  [1, 0],   // down  (index 3)
];

// visited: set of "x,y,dir" strings — if Carl revisits the same state, he's looping
const visited = new Set();

let yes = false;

// Carl's initial state: position (start_x, start_y), facing right (dir=0)
// Note: the queue variable is declared but unused — Carl doesn't BFS, he follows the rule
let [x, y, dir] = [start_x, start_y, 0];

outer:
while (true) {
  // Check if Carl has reached the exit
  if (x === end_x && y === end_y) {
    console.log("1");
    yes = true;
    break outer;
  }

  // LOOP DETECTION: same position + direction = infinite loop
  const currentKey = `${x},${y},${dir}`;
  if (visited.has(currentKey)) {
    break outer; // stuck in a loop → exit with "0"
  }
  visited.add(currentKey);

  // ── PRIORITY 1: Try turning LEFT and stepping forward ──────────────
  // Turn left = rotate CCW = (dir + 1) % 4
  const rotate_left = (dir + 1) % 4;
  let [shift_x, shift_y] = [x + directions[rotate_left][0], y + directions[rotate_left][1]];

  if (
    shift_x >= 0 && shift_x < rows &&   // within bounds
    shift_y >= 0 && shift_y < cols &&
    map2d[shift_x][shift_y] == "0"       // cell is open ('0' = passable)
  ) {
    x = shift_x;     // move to the new cell
    y = shift_y;
    dir = rotate_left; // now facing left direction
    continue;
  }

  // ── PRIORITY 2: Try going STRAIGHT (same direction) ─────────────────
  [shift_x, shift_y] = [x + directions[dir][0], y + directions[dir][1]];

  if (
    shift_x >= 0 && shift_x < rows &&
    shift_y >= 0 && shift_y < cols &&
    map2d[shift_x][shift_y] == "0"
  ) {
    x = shift_x; // move forward, direction unchanged
    y = shift_y;
    continue;
  }

  // ── PRIORITY 3: Turn RIGHT in place (don't move, just rotate) ───────
  // Turn right = rotate CW = (dir - 1 + 4) % 4
  // +4 prevents negative modulo in JavaScript
  const rotate_right = (dir - 1 + 4) % 4;
  dir = rotate_right; // rotate only, position unchanged
  // Will retry from current cell next iteration
}

if (!yes) {
  console.log("0"); // never reached the exit (loop detected)
}
