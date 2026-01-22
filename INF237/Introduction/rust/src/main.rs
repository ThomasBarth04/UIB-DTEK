use std::{
    collections::{HashMap, HashSet},
    io::{self, Read},
};

fn main() {
    let mut input: String = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    let mut tree: HashMap<i32, Vec<i32>> = HashMap::new();
    let lines: Vec<&str> = input.lines().collect();
    let n: usize = lines[0].parse::<usize>().unwrap();

    for i in 1..n {
        let nums: Vec<i32> = lines[i]
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();

        let (a, b) = (nums[0], nums[1]);
        if !tree.contains_key(&a) {
            tree.insert(a, Vec::new());
        }
        if !tree.contains_key(&b) {
            tree.insert(b, Vec::new());
        }

        tree.get_mut(&a).unwrap().push(b);
        tree.get_mut(&b).unwrap().push(a);
    }

    let mut level_map: HashMap<i32, i32> = HashMap::new();
    let start: i32 = 0;
    let queue = vec![[0, 0]];
    let mut visited: HashSet<i32> = HashSet::new();
    visited.insert(start);
    let level_count: Vec<i32> = Vec::new();
}
