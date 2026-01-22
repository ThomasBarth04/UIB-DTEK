use std::collections::HashMap;
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    let mut map: HashMap<i32, i32> = HashMap::new();
    let lines: Vec<&str> = input.lines().collect();

    let n: i32 = lines[0].parse::<i32>().unwrap();
    println!("{}", n);
}
