use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cli {
    Honeypot {
        ip: String,
    },
    Server {
        #[arg(long)]
        bind: String,
        #[arg(long)]
        proxy: String,
    },
    Client {
        #[arg(long)]
        bind: String,
        #[arg(long)]
        server: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        trust_new: bool,
    },
}
