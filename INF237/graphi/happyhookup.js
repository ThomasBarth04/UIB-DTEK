// =============================================================
// HAPPY HOOKUP — Bidirectional BFS on a Directed Graph
// =============================================================
//
// PROBLEM: Given a directed tree and two starting nodes (start_a, start_b),
//          find a node reachable from BOTH start_a and start_b via directed edges.
//          Output "yes" and that node, or "no" if no such node exists.
//
// ALGORITHM: Bidirectional BFS
//   Run two BFS searches simultaneously — one from start_a, one from start_b.
//   Alternate expanding one level of each BFS per iteration.
//   Stop as soon as one BFS reaches a node the OTHER BFS has already visited.
//
// WHY BIDIRECTIONAL?
//   Standard BFS from one source finds all reachable nodes in O(V+E).
//   Bidirectional BFS stops early: as soon as the frontiers MEET, we're done.
//   In practice this is much faster than running two separate full BFS passes.
//
// DIAGRAM:
//
//   Directed tree:  1→3, 1→4, 2→3, 2→5
//   start_a=1, start_b=2
//
//   Round 1:
//     BFS-A expands node 1 → visits {3, 4}. Is 3 in reachable_from_b? No yet.
//     BFS-B expands node 2 → visits {3, 5}. Is 3 in reachable_from_a? YES → output "yes\n3"
//
// STATE:
//   reachable_from_a / reachable_from_b: sets of ALL nodes ever added to each BFS queue
//   visited_a / visited_b: sets of nodes already EXPANDED (neighbours processed)
//   queue_a / queue_b: BFS queues (implemented as arrays with a head pointer)
//   head_a / head_b: array index of the next node to expand (avoids shift() cost)
//
// NOTE: Using head pointer instead of queue.shift() makes this O(1) per dequeue
//       instead of O(n) for array shift.
//
// TIME:  O(V + E) worst case, typically much faster due to early termination
// SPACE: O(V)
// =============================================================

const fs = require('fs');

const input = fs.readFileSync(0, 'utf-8')
const lines = input.trim().split('\n')

// Parse: first line has format "? n" where n = number of directed edges
const n = parseInt(lines[0].split(" ")[1])

// Build adjacency list (directed graph stored as Map: node → [children])
const tree = new Map();
for (let i = 1; i <= n; i++) {
  const [a, b] = lines[i].split(' ').map(Number);
  if (!tree.has(a)) tree.set(a, []);
  tree.get(a).push(b); // directed edge a → b
}

// Last line: the two starting nodes
const [start_a, start_b] = lines.at(-1).split(" ").map(Number);

// reachable_from_x: ALL nodes that BFS-x has ever enqueued (includes frontier)
// This is checked BEFORE expansion to detect meetings as early as possible
const reachable_from_a = new Set([start_a]);
const reachable_from_b = new Set([start_b]);

// BFS queues (array used as queue; head pointer avoids costly array.shift())
const queue_a = [start_a];
const queue_b = [start_b];
head_a = 0; // index of next node to expand in queue_a
head_b = 0; // index of next node to expand in queue_b

// visited_x: nodes already EXPANDED (their neighbours have been processed)
const visited_a = new Set();
const visited_b = new Set();

let yes = false;

// Alternate expanding BFS-A and BFS-B until one side's frontier meets the other
outer:
while (head_a < queue_a.length || head_b < queue_b.length) {

  // ── Expand one node from BFS-A ──────────────────────────────────────
  if (head_a < queue_a.length) {
    const a = queue_a[head_a++] // dequeue next node (O(1) with head pointer)
    visited_a.add(a);

    for (let val of tree.get(a) ?? []) { // ?? [] handles nodes with no outgoing edges
      // If this neighbour was already reached by BFS-B → MEETING POINT found
      if (reachable_from_b.has(val)) {
        console.log("yes\n" + val);
        yes = true;
        break outer;
      }

      // Otherwise enqueue val for BFS-A (if not already seen)
      if (!visited_a.has(val)) {
        queue_a.push(val);
        reachable_from_a.add(val); // mark as reachable so BFS-B can detect it
      }
    }
  }

  // ── Expand one node from BFS-B ──────────────────────────────────────
  if (head_b < queue_b.length) {
    const b = queue_b[head_b++]
    visited_b.add(b);

    for (let val of tree.get(b) ?? []) {
      // If this neighbour was already reached by BFS-A → MEETING POINT found
      if (reachable_from_a.has(val)) {
        console.log("yes\n" + val);
        yes = true;
        break outer;
      }
      if (!visited_b.has(val)) {
        queue_b.push(val);
        reachable_from_b.add(val);
      }
    }
  }
}

// Both BFS searches exhausted without finding a common reachable node
if (!yes) { console.log("no") };
