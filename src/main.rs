mod cli;
mod crypto;
mod error;
mod streaming;
mod types;
mod util;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}
