/*
*   Purpose: A learning project to write my own directory enumeration tool.
*               Pass a hash value and a word list to crack hashed passwords!
*               Can also be used to quickly generate hashes of a wordlist (not implemented yet)
*
*   Author: Mauzy0x00
*   Date:   6.18.2025
*
*/

// IO
use std::fs::File;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

// use std::time::Duration;
use smol::stream;

// CLI
use anyhow::{Result, Context};
use log::{info, warn};

// Networking 
use reqwest::Client;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'u', long = "url", help = "Target URL")]
    url: String,

    #[arg(short = 'w', long = "wordlist", default_value = "/usr/share/SecLists/Discovery/Web-Content/dirsearch.txt",  help = "Path to the wordlist")]
    wordlist_path: PathBuf,

    #[arg(short = 't', long = "concurrency", default_value = "50", help = "Concurrency fine tuning")]
    concurrency: u8,

    #[arg(short = 'v', long = "verbose", help = "Verbose output")]
    verbose: bool,
}

fn main() -> Result<()> {
    smol::block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args = Args::parse();
    let base_url = args.url.trim_end_matches('/').to_string();
    let wordlist_path = PathBuf::from(&args.wordlist_path);
    let concurrency = args.concurrency;

    if !wordlist_path.exists() {
        panic!("Wordlist not found at: {}", wordlist_path.display());
    }

    println!("[+] Loading wordlist into memory");
    let string_wordlist = std::fs::read_to_string(&wordlist_path)
        .with_context(|| format!("Cannot read file: `{}`", wordlist_path.display()))?;

    let client = Client::new();

    let paths: Vec<String> = string_wordlist
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    println!("[+] Fuzzing {} paths with {} concurrency", paths.len(), concurrency);

    stream::iter(paths)
        .map(|path| {
            let client = &client;
            let full_url = format!("{}/{}", base_url, path);
            async move {
                match client.get(&full_url).send().await {
                    Ok(res) => {
                        let code = res.status();
                        if code != 404 {
                            println!("{} -> {}", full_url, code);
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] Error for {}: {}", full_url, e);
                    }
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    Ok(())
}


fn initialize() {
    env_logger::init();
    info!("Starting log...");
    warn!("Ayeee a warning!");

    let banner = r#"
        ooooooooo.                 .   oooo        oooooooooooo  o8o                    .o8                    
        `888   `Y88.             .o8   `888        `888'     `8  `"'                   "888                    
        888   .d88'  .oooo.   .o888oo  888 .oo.    888         oooo  ooo. .oo.    .oooo888   .ooooo.  oooo d8b
        888ooo88P'  `P  )88b    888    888P"Y88b   888oooo8    `888  `888P"Y88b  d88' `888  d88' `88b `888""8P
        888          .oP"888    888    888   888   888    "     888   888   888  888   888  888ooo888  888    
        888         d8(  888    888 .  888   888   888          888   888   888  888   888  888    .o  888    
        o888o        `Y888""8o   "888" o888o o888o o888o        o888o o888o o888o `Y8bod88P" `Y8bod8P' d888b  

    "#;

    println!("{banner}");
}

async fn web_request(client: Client, url: String) -> Result<()> {
    let body = reqwest::get("https://www.rust-lang.org")
    .await?
    .text()
    .await?;

    println!("body = {body:?}");


    Ok(())
}