mod dns;
mod server;

fn main() {
    if let Err(e) = server::run() {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}
