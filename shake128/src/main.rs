use std::io::stdin;

use shake128::shake128;

fn main() {
    let Some(num_bytes) = std::env::args()
        .nth(1)
        .and_then(|x| x.parse::<usize>().ok())
    else {
        eprintln!("Usage: shake128 <n>");
        std::process::exit(1)
    };

    let hash = shake128(stdin().lock()).expect("Could not read data from stdin");

    for output in hash.take(num_bytes) {
        print!("{output:02x}");
    }
    println!()
}
