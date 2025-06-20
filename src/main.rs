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

use clap::Parser;

// use std::time::Duration;

// CLI
use anyhow::{Result, Context};
use log::{info, warn};

// Networking 
use reqwest::Client;

fn main() -> Result<()> {

    initialize();

    let default_wordlist_path = PathBuf::from("/usr/share/SecLists/Discovery/Web-Content/dirsearch.txt"); // .exists calls fs::metadata(path).is_ok()


    println!("[+] Loading wordlist into memory");
    let string_wordlist = std::fs::read_to_string(&default_wordlist_path).with_context(|| format!("File is unreadable! File: `{}`", default_wordlist_path.display()))?;
    
    // Create client 
    let client = Client::builder().build()?;

    // Loop web_requests
    for line in string_wordlist.lines() {
        web_request();
    }

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

async fn web_request() -> Result<()> {
    let body = reqwest::get("https://www.rust-lang.org")
    .await?
    .text()
    .await?;

    println!("body = {body:?}");


    Ok(())
}