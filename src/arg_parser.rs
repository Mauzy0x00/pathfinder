use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    DirectoryScan {
        #[arg(
            short = 'u',
            long = "url",
            help = "Target URL (ex. '-u mauzy.net' or '-u 10.10.192.251"
        )]
        host: String,

        #[arg(short = 'p', long = "port", default_value = "80", help = "Target port")]
        port: u16,

        #[arg(
            short = 'w',
            long = "wordlist",
            default_value = "./combined_words.txt",
            help = "Path to the wordlist"
        )]
        wordlist_path: PathBuf,

        #[arg(
            short = 't',
            long = "threads",
            default_value = "50",
            help = "Number of worker threads"
        )]
        thread_count: usize,

        #[arg(
            short = 'o',
            long = "output",
            help = "Path to the output file (optional)"
        )]
        output_file: Option<String>,

        #[arg(short = 'v', long = "verbose", help = "Verbose output")]
        verbose: bool,
    },

    /// Scan for subdomains
    SubdomainScan {
        #[arg(
            short = 'u',
            long = "url",
            help = "Target URL (ex. '-u mauzy.net' or '-u 10.10.192.251"
        )]
        host: String,

        #[arg(short = 'p', long = "port", default_value = "80", help = "Target port")]
        port: u16,

        #[arg(
            short = 'w',
            long = "wordlist",
            default_value = "./combined_words.txt",
            help = "Path to the wordlist"
        )]
        wordlist_path: PathBuf,

        #[arg(
            short = 'o',
            long = "output",
            help = "Path to the output file (optional)"
        )]
        output_file: Option<String>,

        #[arg(
            short = 't',
            long = "threads",
            default_value = "50",
            help = "Number of worker threads"
        )]
        thread_count: usize,

        #[arg(short = 'v', long = "verbose", help = "Verbose output")]
        verbose: bool,
    },
}
