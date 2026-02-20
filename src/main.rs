/*
*   Purpose: A learning project to write my own directory enumeration tool.
*            Note: Using more than 50 concurent threads turns this program instantly into a DoS tool against the target. Use with caution and at your own risk.
*                   A test with 100 threads broke the OWASP juice shop.
*
*   Author: Mauzy0x00
*   Date:   6.18.2025
*
*/

/* TODO:
    - Fix port formatting in the request string -- Omit port 80 and 443 from request string? 
    - Refactor code
    - Rate Limiting Detection: Calculate average reqeust time, over time. Inform user of detection; research options to work around this
    - Crawling: If a directory is found, add it to the queue of directories to fuzz (ex. if /admin is found, add /admin/ to the queue)
    - Option to output to file (create if non-existent)
    - Option for custom request string (?)
*/

// IO
use std::fs::File;

#[cfg(windows)]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::path::PathBuf;

use clap::Parser;

use smol::{Async, prelude::*};

// CLI
use anyhow::Result;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{info, warn};

// Networking
use std::net::{TcpStream, ToSocketAddrs};

use std::result::Result::Ok;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
// use std::sync::atomic::{AtomicBool, Ordering};

mod arg_parser;
use arg_parser::{Args, Commands};

fn main() -> Result<()> {
    initialize();

    // Parse runtime arguments
    let args = Args::parse();

    match args.command {
        Some(Commands::DirectoryScan {
            host,
            port,
            wordlist_path,
            thread_count,
            output_file,
            verbose,
        }) => {
            let is_subdomain = false;

            println!("Target: {host}:{port}");

            enumerate(
                &host,
                port,
                is_subdomain,
                wordlist_path,
                thread_count,
                &output_file,
                verbose,
            )?;
        }

        Some(Commands::SubdomainScan {
            host,
            port,
            wordlist_path,
            thread_count,
            output_file,
            verbose,
        }) => {
            let is_subdomain = true;

            println!("Target: {host}:{port}");

            enumerate(
                &host,
                port,
                is_subdomain,
                wordlist_path,
                thread_count,
                &output_file,
                verbose,
            )?;
        }

        None => {
            println!("No command provided. Use --help for more information.");
        }
    }

    Ok(())
}

// Plz look at thread pool implementation from ripsaw
fn enumerate(
    host: &str,
    port: u16,
    is_subdomain: bool,
    wordlist_path: PathBuf,
    thread_count: usize,
    _output_string: &Option<String>,
    verbose: bool,
) -> Result<()> {
    // Open passed wordlist file
    println!("[+] Processing the wordlist");
    
    // Open the path in read-only mode, returns `io::Result<File>`
    let wordlist_file = File::open(&wordlist_path)?;
    let file_size = wordlist_path.metadata()?.len();
    println!("File size: {file_size}");

    // Count lines from a separate reader
    let wordlist_line_count = BufReader::new(File::open(&wordlist_path)?)
        .lines()
        .count();

    let partition_size = file_size / thread_count as u64; // Get the  size of each thread partition

    if verbose {
        println!("Partition size per thread: {partition_size}");
        println!("[+] Building threads...");
    }

    // Creeate a struct of the progress bar(s) to be shared across threads and add the progress bar to it
    let multi_progress = MultiProgress::new();

    let style = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
    )
    .unwrap()
    .progress_chars("#>-");

    let progress_bar = multi_progress.add(ProgressBar::new(wordlist_line_count as u64)); // Add a progress bar to count the number of lines in the wordlist (total requests to be made)
    progress_bar.set_style(style.clone());
    progress_bar.set_message("Wordlist Progress");

    // Prepare for multithreading
    let mut handles: Vec<JoinHandle<()>> = vec![]; // A vector of thread handles
    let mutex_wordlist_file = Arc::new(Mutex::new(wordlist_file)); // Wrap the Mutex in Arc for mutual excusion of the file and an atomic reference across threads

    // Start worker threads
    for thread_id in 0..thread_count {
        let host = String::from(host);
        let wordlist_file = Arc::clone(&mutex_wordlist_file); // Create a clone of the mutex_worldist_file: Arc<Mutex><File>> for each thread
        let progress_bar = progress_bar.clone(); // A clone of the struct contianing progress bars
        let multi_progress = multi_progress.clone(); // A clone of the struct contianing progress bars
        let handle = std::thread::Builder::new()
            .name(format!("Enumeration_thread_{}", thread_id))
            .spawn(move || {
                // Calculate current thread's assigned memory space (assigned partition)
                let start = thread_id as u64 * partition_size;

                // If the current thread is the last thread, set the end to the true end of the file, not the calculated end
                let end = if thread_id == thread_count - 1 {
                    file_size
                } else {
                    (thread_id as u64 + 1) * partition_size
                };

                // Request and lock the file
                if verbose {
                    println!("[+] Thread {thread_id} is now reading from wordlist");
                }

                let mut wordlist_file = wordlist_file.lock().unwrap();

                // Count how many lines are in this current partition
                let line_count: usize =
                    match count_lines_in_partition(&mut wordlist_file, start, end) {
                        Err(why) => panic!(
                            "Error counting lines on thread {} because {}",
                            thread_id, why
                        ),
                        Ok(line_count) => line_count,
                    };

                let mut lines: Vec<String> = Vec::with_capacity(line_count); // Allocate a vector of that size (more efficient to pre-allocate and not allocate each entry)

                // Read lines of partition into the vector
                wordlist_file
                    .seek(SeekFrom::Start(start))
                    .expect("Failed to seek to partition start."); // Move the position of the file read

                let mut buf_reader = BufReader::new(&*wordlist_file); // Create a reading buffer to the file pointer

                let mut current_position = start;
                while current_position < end {
                    let mut line = String::new();
                    let bytes_read = buf_reader
                        .read_line(&mut line)
                        .expect("Failed to read line");

                    if bytes_read == 0 {
                        break;
                    }

                    lines.push(line.trim().to_string());

                    current_position += bytes_read as u64;

                    if current_position >= end {
                        break;
                    }
                }

                if verbose {
                    println!(
                        "[+] Thread {thread_id} finished reading {} lines.",
                        lines.len()
                    );
                }

                // Unlock the file and iterate over vector
                drop(wordlist_file); // Drop is now the owner and its scope has ended. So is this not neccessary and the lock is freed after the seek and read?

                if verbose {
                    println!("[+] Starting to request on thread {thread_id}");
                }

                // Make a request for each directory in the word list
                for target in lines 
                {   
                    // if we are in subdomain mode, craft a subdomain request. Otherwise craft directory reqeust
                    let request_string = if is_subdomain {
                        format!(
                        "GET / HTTP/1.1\r\nHost: {}.{}:{}\r\nConnection: keep-alive\r\n\r\n",
                        target, host, port
                        )
                    } else {
                        format!(
                        "GET /{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: keep-alive\r\n\r\n",
                        target, host, port
                        )
                    };

                    if verbose { println!("Request string: {}", request_string); }
                    
                    // Asynchronously make the web request and read the status code
                    if let Ok(status_code) = smol::block_on(web_request(&host, port, &request_string)) {
                        match status_code[0] {
                            2 => {
                                let _ = multi_progress.println(format!(
                                    "{host}/{target}  -----------------------------  Status code: 2{}{}\n",
                                        status_code[1], status_code[2]
                                    ));
                            }
                            3 => {
                                if status_code[2] != 1 {
                                    // Ignore permanently moved links [301]
                                    let _ = multi_progress.println(format!(
                                            "{host}/{target}  -----------------------------  Status code: 3{}{}\n",
                                            status_code[1], status_code[2]
                                        ));

                                }
                                
                            }
                            _ => {} // Ignore other status codes
                        }
                    }

                    progress_bar.inc(1);
                }
            })?; // End of thread

        handles.push(handle); // Push the handles out of the for loop context so they may be joined
    }

    for handle in handles {
        handle.join().expect("Thread panicked ")
    }

    progress_bar.finish_with_message("Enumeration complete");

    Ok(())
}

/// Attempts to make a web request and returns 3 bytes representing the status code (ex. [2, 0, 0] for 200)
async fn web_request(host: &str, port: u16, request_string: &String) -> Result<[u8; 3]> {
    // Create a connection stream to the base url
    let host_addr = String::from(host);
    let mut addrs = smol::unblock(move || (host_addr, port).to_socket_addrs()).await?;
    let addr = addrs.next().unwrap();
    let mut stream = Async::<TcpStream>::connect(addr).await?;

    // Send an HTTP GET request.
    stream.write_all(request_string.as_bytes()).await?;

    // Read the response
    let mut bytes_buffer = vec![0; 1024];
    stream.read(&mut bytes_buffer).await?;

    let status_code = read_status_code(bytes_buffer)?;

    Ok(status_code)
}

fn read_status_code(bytes_buffer: Vec<u8>) -> Result<[u8; 3]> {
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
        } else if header_index > 0 {
            // Reset the header index if the first byte matches but the next byte does not
            header_index = 0;
        }
        buffer_index += 1;
    }

    buffer_index += 5; // Skip past HTTP version bytes
    // Next 3 bytes will be the status code

    let mut status_code = [0; 3];
    let mut status_index: usize = 0;
    // Fill the status code array from the byte_buffer vector
    loop {
        // println!("status_code value  = {} ... status index = {}", status_code[status_index], status_index);
        // println!("bytes_buffer value = {} ... buffer index = {}", bytes_buffer[buffer_index], buffer_index);
        status_code[status_index] = bytes_buffer[buffer_index] - 48; // Subtract 48 to get ascii value
        status_index += 1;
        buffer_index += 1;

        if status_index >= 3 {
            break;
        }
    }

    Ok(status_code)
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

fn process_wordlist(wordlist_path: PathBuf, thread_count: usize) -> Result<u64> {
        println!("[+] Processing the wordlist");
    // Open the path in read-only mode, returns `io::Result<File>`
    let wordlist_file = match File::open(&wordlist_path) {
        Err(why) => panic!("couldn't open {}: {}", wordlist_path.display(), why),
        Ok(file) => file,
    };
    // Get the size of the input wordlist
    let file_size = wordlist_path.metadata().unwrap().len();
    println!("File size: {file_size}");

    // Probably a better way to do this... proof of concept atm
    let file = File::open("combined_words.txt")?;
    let reader = BufReader::new(file);

    let mut wordlist_line_count = 0;
    for _ in reader.lines() {
        wordlist_line_count += 1;
    }

    let partition_size = file_size / thread_count as u64; // Get the  size of each thread partition

    Ok(partition_size)
} 

use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
/// Count how many lines are in the portion of the file that was partitioned to each thread
// Refactored function to increase readability of the large wordlist crack function
fn count_lines_in_partition(file: &mut File, start: u64, end: u64) -> io::Result<usize> {
    file.seek(SeekFrom::Start(start))?;
    let mut buf_reader = BufReader::new(file);
    let mut line_count: usize = 0;
    let mut current_position = start;

    while current_position < end {
        let mut line = String::new();
        let bytes_read = buf_reader.read_line(&mut line)?;
        if bytes_read == 0 {
            break; // EOF reached
        }
        line_count += 1;
        current_position += bytes_read as u64;
        if current_position >= end {
            break;
        }
    }
    Ok(line_count)
} // end count_lines_in_partition
