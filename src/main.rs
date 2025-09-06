/*
*   Purpose: A learning project to write my own directory enumeration tool.
*               Pass a hash value and a word list to crack hashed passwords!
*               Can also be used to quickly generate hashes of a wordlist (not implemented yet)
*
*   Author: Mauzy0x00
*   Date:   6.18.2025
*
*/

/* TODO:

    - Rate Limiting Detection: Calculate average reqeust time, over time. Inform user of detection; research options to work around this
    - Progess bar
    - Option to output to file (create if non-existent)
    - Option for custom request string (?)

*/


// IO
use std::fs::File;
#[cfg(windows)]
use std::{os::windows::thread, path::PathBuf};
use std::path::PathBuf;
use clap::{Parser};

// use reqwest::header::HOST;
// use std::time::Duration;
use smol::{prelude::*, Async};

// CLI
use anyhow::{Result, Context};
use log::{info, warn};
use indicatif::ProgressBar;
use std::time::Duration;

// Networking 
use std::net::{TcpStream, ToSocketAddrs};

use std::result::Result::Ok;
use std::thread::JoinHandle;
use std::sync::{Arc, Mutex};
// use std::sync::atomic::{AtomicBool, Ordering};


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'u', long = "host", help = "Target host (ex. '-u mauzy.net' or '-u 10.10.192.251")]
    host: String,

    #[arg(short = 'p', long = "port", default_value = "80", help = "Target port")]
    port: u16,

    #[arg(short = 'w', long = "wordlist", default_value = "./combined_words.txt",  help = "Path to the wordlist")]
    wordlist_path: PathBuf,

    #[arg(short = 't', long = "threads", default_value = "10",  help = "Number of worker threads")]
    thread_count: usize,

    #[arg(short = 'v', long = "verbose", help = "Verbose output")]
    verbose: bool,
}

fn main() -> Result<()> {
    initialize();
    
    // Parse runtime arguments
    let args = Args::parse();
    let host: &str = args.host.trim_end_matches('/');
    let port = args.port;
    let wordlist_path = args.wordlist_path;
    let thread_count = args.thread_count;
    let verbose = args.verbose;

    println!("Target: {host}:{port}");

    // Open passed wordlist file
    println!("[+] Processing the wordlist");
    // Open the path in read-only mode, returns `io::Result<File>`
    let wordlist_file = match File::open(&wordlist_path) {
        Err(why) => panic!("couldn't open {}: {}", wordlist_path.display(), why),
        Ok(file) => file,
    };

    // Get the size of the input wordlist
    let file_size = wordlist_path.metadata().unwrap().len();
    println!("File size: {file_size}");

    //let bar = ProgressBar::new(file_size);

    enumerate_web_directories(wordlist_file, file_size, host, port, thread_count, verbose)?;    // Multithreaded function

    Ok(())
}

// Plz look at thread pool implementation from ripsaw
fn enumerate_web_directories(wordlist_file: File, file_size:u64, host: &str, port: u16, thread_count: usize, verbose: bool) -> Result<()> {

    let partition_size = file_size / thread_count as u64; // Get the  size of each thread partition

    if verbose {
        println!("Partition size per thread: {partition_size}");
        println!("[+] Building threads...");
    }

    let mutex_wordlist_file = Arc::new(Mutex::new(wordlist_file)); // Wrap the Mutex in Arc for mutual excusion of the file and an atomic reference across threads

    let mut handles: Vec<JoinHandle<()>> = vec![]; // A vector of thread handles

    for thread_id in 0..thread_count {
        let wordlist_file = Arc::clone(&mutex_wordlist_file);   // Create a clone of the mutex_worldist_file: Arc<Mutex><File>> for each thread
        let host = String::from(host);
        
        let handle = std::thread::spawn(move || {

            let bar = ProgressBar::new_spinner();
            bar.enable_steady_tick(Duration::from_millis(100));

            // Calculate current thread's assigned memory space (assigned partition)
            let start = thread_id as u64 * partition_size; 

            // If the current thread is the last thread, set the end to the true end of the file, not the calculated end
            let end = if thread_id == thread_count - 1 {
                                file_size
                            } else {
                                (thread_id as u64 + 1) * partition_size
                            };

            // Request and lock the file
            if verbose { println!("[+] Thread {thread_id} is now reading from wordlist"); }
            let mut wordlist_file = wordlist_file.lock().unwrap();

            // Count how many lines are in this current partition
            let line_count:usize = match count_lines_in_partition(&mut wordlist_file, start, end) {
                Err(why) => panic!("Error counting lines on thread {} because {}", thread_id, why),
                Ok(line_count) => line_count,
            };

            let mut lines:Vec<String> = Vec::with_capacity(line_count);  // Allocate a vector of that size (more efficient to pre-allocate and not allocate each entry)
            
            // Read lines of partition into the vector
            wordlist_file.seek(SeekFrom::Start(start)).expect("Failed to seek to partition start.");    // Move the position of the file read

            let mut buf_reader = BufReader::new(&*wordlist_file); // Create a reading buffer to the file pointer


            let mut current_position = start;
            while current_position < end {
                let mut line = String::new();
                let bytes_read = buf_reader.read_line(&mut line).expect("Failed to read line");

                if bytes_read == 0 {
                    break;
                }

                lines.push(line.trim().to_string());

                current_position += bytes_read as u64;

                if current_position >= end {
                    break;
                }
            }

            if verbose { println!("[+] Thread {thread_id} finished reading {} lines.", lines.len()); }

            // Unlock the file and iterate over vector
            drop(wordlist_file); // Drop is now the owner and its scope has ended. So is this not neccessary and the lock is freed after the seek and read?

            if verbose { println!("[+] Starting to request on thread {thread_id}"); }
            
            // Make a request for each directory in the word list
            for directory in lines.iter() {
                // need async stuff for this I think
                match smol::block_on(web_request(&host, directory, port)) {
                    Err(why) => panic!("Request failed: {}", why),
                    Ok(_) => (),
                };
            }

        }); // End of thread

        handles.push(handle);   // Push the handles out of the for loop context so they may be joined
    }

    for handle in handles {
        handle.join().expect("Thread panicked ")
    }
    
    Ok(())
}

async fn web_request(host: &str, directory: &String, port: u16) -> Result<()> {
    // Create a connection stream to the base url
    let host_addr = String::from(host);
    let mut addrs = smol::unblock(move || (host_addr, port).to_socket_addrs()).await?;
    let addr = addrs.next().unwrap();
    let mut stream = Async::<TcpStream>::connect(addr).await?;

    // Format the request
    let request_string = format!("GET /{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: keep-alive\r\n\r\n", directory, host, port);

    // Send an HTTP GET request.
    stream.write_all(request_string.as_bytes()).await?;

    // Read the response
    let mut bytes_buffer = vec![0; 1024];
    stream.read(&mut bytes_buffer).await?;

    let status_code = read_status_code(bytes_buffer)?;
    
    match status_code[0]{
        2 => println!("{host}/{directory}  -----------------------------  Status code: 2{}{} \n", status_code[1], status_code[2]),  // 2xx
        3 => if status_code[2] == 1 { // Ignore permanently moved links [301]
                } else { println!("{host}/{directory}  -----------------------------  Status code: 3{}{} \n", status_code[1], status_code[2])},  // 3xx
        // 52 => println!("{host}/{path}  -----------------------------  Status code: {:?} \n", status_code),     // 4xx
        _  => ()
    }

    Ok(())
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
        status_code[status_index] = bytes_buffer[buffer_index] - 48;    // Subtract 48 to get ascii value
        status_index += 1;    buffer_index += 1;
        
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


use std::io::{self, BufReader, Seek, SeekFrom, BufRead};
/// Count how many lines are in the portion of the file that was partitioned to each thread
// Refactored function to increase readability of the large wordlist crack function
fn count_lines_in_partition(file: &mut File, start: u64, end: u64) -> io::Result<usize> {
    file.seek(SeekFrom::Start(start))?;
    let mut buf_reader = BufReader::new(file);
    let mut line_count:usize = 0;
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



// async fn async_main(wordlist_path: PathBuf, host: String, port: u16) -> Result<()> {

//     // Load the wordlist into working memory (String)
//     println!("[+] Loading wordlist into memory");
//     let string_wordlist = std::fs::read_to_string(&wordlist_path)
//         .with_context(|| format!("Cannot read file: `{}`", wordlist_path.display()))?;

//     // Convert the String to a Vector of Strings
//     let paths: Vec<String> = string_wordlist
//         .lines()
//         .map(|line| line.trim().to_string())
//         .filter(|line| !line.is_empty())
//         .collect();

//     println!("[+] Fuzzing {} paths", paths.len());c

//     for path in paths {
        
//         // Create a connection stream to the base url
//         let host_addr = host.clone();
//         let mut addrs = smol::unblock(move || (host_addr, port).to_socket_addrs()).await?;
//         let addr = addrs.next().unwrap();
//         let mut stream = Async::<TcpStream>::connect(addr).await?;

//         // Format the request
//         let request_string = format!("GET /{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: keep-alive\r\n\r\n", path, host, port);

//         // Send an HTTP GET request.
//         stream.write_all(request_string.as_bytes()).await?;

//         // Read the response
//         let mut bytes_buffer = vec![0; 1024];
//         stream.read(&mut bytes_buffer).await?;

//         let status_code = read_status_code(bytes_buffer).await?;
        
//         match status_code[0]{
//             50 => println!("{host}/{path}  -----------------------------  Status code: {:?} \n", status_code),     // 2xx
//             51 => println!("{host}/{path}  -----------------------------  Status code: {:?} \n", status_code),     // 3xx
//             // 52 => println!("{host}/{path}  -----------------------------  Status code: {:?} \n", status_code),     // 4xx
//             _  => ()
//         }
//     }

//     Ok(())
// }