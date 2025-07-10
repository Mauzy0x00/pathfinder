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
use std::path::PathBuf;

use clap::{Parser};

// use std::time::Duration;
use smol::{prelude::*, Async};

// CLI
use anyhow::{Result, Context};
use log::{info, warn};

// Networking 
use std::net::{TcpStream, ToSocketAddrs};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'u', long = "host", help = "Target host (ex. '-u mauzy.net' or '-u 10.10.192.251")]
    host: String,

    #[arg(short = 'p', long = "port", default_value = "80", help = "Target port")]
    port: u16,

    #[arg(short = 'w', long = "wordlist", default_value = "./combined_words.txt",  help = "Path to the wordlist")]
    wordlist_path: PathBuf,

    #[arg(short = 'v', long = "verbose", help = "Verbose output")]
    verbose: bool,
}

fn main() -> Result<()> {
    initialize();
    
    // Parse runtime arguments
    let args = Args::parse();
    let host = args.host.trim_end_matches('/').to_string();
    let port = args.port;
    let wordlist_path = args.wordlist_path;

    smol::block_on(async_main(wordlist_path, host, port))
}

async fn async_main(wordlist_path: PathBuf, host: String, port: u16) -> Result<()> {

    // Check to make sure the wordlist exists
    if !wordlist_path.exists() {
        panic!("Wordlist not found at: {}", wordlist_path.display());
    }

    // Load the wordlist into working memory (String)
    println!("[+] Loading wordlist into memory");
    let string_wordlist = std::fs::read_to_string(&wordlist_path)
        .with_context(|| format!("Cannot read file: `{}`", wordlist_path.display()))?;

    // Convert the String to a Vector of Strings
    let paths: Vec<String> = string_wordlist
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    println!("[+] Fuzzing {} paths", paths.len());


    for path in paths {
        
        // Create a connection stream to the base url
        let host_addr = host.clone();
        let mut addrs = smol::unblock(move || (host_addr, port).to_socket_addrs()).await?;
        let addr = addrs.next().unwrap();
        let mut stream = Async::<TcpStream>::connect(addr).await?;

        // Format the request
        let request_string = format!("GET /{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: keep-alive\r\n\r\n", path, host, port);

        // Send an HTTP GET request.
        stream.write_all(request_string.as_bytes()).await?;

        // Read the response
        let mut bytes_buffer = vec![0; 1024];
        stream.read(&mut bytes_buffer).await?;

        let status_code = read_status_code(bytes_buffer).await?;
        
        match status_code[0]{
            50 => println!("{host}/{path}  -----------------------------  Status code: {:?} \n", status_code),     // 2xx
            51 => println!("{host}/{path}  -----------------------------  Status code: {:?} \n", status_code),     // 3xx
            // 52 => println!("{host}/{path}  -----------------------------  Status code: {:?} \n", status_code),     // 4xx
            _  => ()
        }
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


async fn read_status_code(bytes_buffer: Vec<u8>) -> Result<[u8; 3]> { 

    // println!("[+] READ_STATUS_CODE ENTRY");

    // Read in 4 bytes at a time
    // Search for the HTTP header
    let http_header = "\x48\x54\x54\x50".as_bytes();
    let mut buffer_index = 0;
    let mut header_index = 0;
    for _bytes in &bytes_buffer {
        
        if header_index == 4 {
            // Header found
            // println!("[+] HTTP Header Found");
            break;
        }
        if bytes_buffer[buffer_index] == http_header[header_index] {
            // Current buffer index matches header we are looking for... increment to check the next one
            // println!("bytes_buffer value= {} ... http_header value = {}", bytes_buffer[buffer_index], http_header[header_index]);
            header_index += 1;
        }
        else if header_index > 0 {  // Reset the header index if the first byte matches but the next byte does not
            header_index = 0;
        }
        buffer_index += 1;
    }

    buffer_index += 5;  // Skip past HTTP version bytes
                        // Next 3 bytes will be the status code

    let mut status_code = [0; 3];
    let mut status_index: usize = 0;
    // Fill the status code array from the byte_buffer vector
    loop {
        // println!("status_code value  = {} ... status index = {}", status_code[status_index], status_index);
        // println!("bytes_buffer value = {} ... buffer index = {}", bytes_buffer[buffer_index], buffer_index);
        status_code[status_index] = bytes_buffer[buffer_index];
        status_index += 1;    buffer_index += 1;
        
        if status_index >= 3 {
            break;
        }
    }

    Ok(status_code)
}