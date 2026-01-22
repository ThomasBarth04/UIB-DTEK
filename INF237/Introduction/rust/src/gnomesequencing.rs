use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    println!("Gnomes:");
    let mut first = true;
    for i in input.lines() {
        if first {
            first = false;
            continue;
        }
        let nums: Vec<i32> = i.split_whitespace().map(|x| x.parse().unwrap()).collect();
        let (a, b, c) = (nums[0], nums[1], nums[2]);

        if (a < b && b < c) || (a > b && b > c) {
            println!("Ordered");
        } else {
            println!("Unordered");
        }
    }
}
