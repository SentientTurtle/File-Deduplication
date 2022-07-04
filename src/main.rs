#![feature(is_some_with)]

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::{fs, io};
use std::fs::FileType;
use std::io::Read;
use std::path::PathBuf;
use clap::{Arg, Command, ErrorKind};
use clap::builder::{OsStringValueParser};
use sha2::{Digest, Sha256};


fn main() {
    let mut app = Command::new("File Deduplicate")
        .about("De-duplicates byte-identical files")
        .arg(
            Arg::new("hash-only")
                .short('h')
                .long("hash-only")
                .takes_value(false)
                .help("Use only SHA-256 hash for file equality; Hash collisions result in file being deleted despite not being identical")
                .required(false)
        )
        .arg(
            Arg::new("directory")
                .help("Directory to de-duplicate")
                .short('d')
                .long("directory")
                .takes_value(true)
                .required(false)
                .value_parser(OsStringValueParser::new())
        )
        .arg(
            Arg::new("FILE EXTENSION")
                // .last(true)
                .help("Only files of specified extension will be de-duplicated.")
                .takes_value(true)
                .required(true)
                .value_parser(OsStringValueParser::new())
        );
    let matches = app.get_matches_mut();

    let hash_only = matches.is_present("hash-only");
    let extension = matches.get_one::<OsString>("FILE EXTENSION");
    if let Some(ext) = extension {
        if !ext.to_string_lossy().starts_with('.') {
            println!("ERROR: Extension must start with a period");
            std::process::exit(1);
        }
    }
    let directory = matches.get_one::<OsString>("directory").map(OsString::as_ref).unwrap_or(OsStr::new("."));

    match deduplicate(extension.map(OsString::as_ref), directory, hash_only) {
        Ok(to_remove) if to_remove.len() > 0 => {
            println!("Confirm deletion (Y/N):");
            let mut buffer = String::new();
            loop {
                match io::stdin().read_line(&mut buffer) {
                    Ok(_) => {
                        let response = buffer.trim();
                        if response == "Y" || response == "y" {
                            for file in to_remove {
                                match fs::remove_file(&file) {
                                    Ok(_) => println!("Removed: {:?}", file.file_name().unwrap()),
                                    Err(err) => println!("Error removing file: {:?} {}", file.file_name().unwrap(), err),
                                }
                            }
                            std::process::exit(0)
                        } else if response == "N" || response == "n" {
                            println!("No files deleted");
                            std::process::exit(0)
                        } else {
                            println!("Confirm deletion (Y/N):");
                            buffer.clear();
                        }
                    }
                    Err(_) => std::process::exit(2)
                }
            }
        }
        Ok(_) => {
            println!("No duplicate files");
            std::process::exit(0)
        }
        Err(err) => {
            println!("ERROR: {}", app.error(ErrorKind::Io, err));
            std::process::exit(1);
        }
    }
}

fn read_buf_exact_or_eof<R: Read>(mut read: R, buffer: &mut [u8; 512]) -> Result<&mut [u8], io::Error> {
    let mut read_index = 0;
    loop {
        if read_index == buffer.len() { return Ok(buffer); }

        match read.read(&mut buffer[read_index..]) {    // Using split-at-mut rather than raw indexing would be safer, but the borrow checker gets confused
            Ok(0) => return Ok(&mut buffer[0..read_index]),
            Ok(n) => read_index += n,
            Err(err) => {
                if let io::ErrorKind::Interrupted = err.kind() {
                    continue;
                } else {
                    return Err(err);
                }
            }
        }
    }
}

fn deduplicate(extension: Option<&OsStr>, directory: &OsStr, hash_only: bool) -> Result<Vec<PathBuf>, io::Error> {
    let directory = fs::read_dir(directory)?;

    let mut to_remove = Vec::new();

    // Group files by size first; Files of different size cannot be equal
    let mut file_size_map = HashMap::new();

    for entry in directory {
        let file = entry?;
        if !file.file_type().is_ok_and(FileType::is_file) { continue; }

        use os_str_bytes::OsStrBytes;
        if let Some(extension) = extension {
            if !file.file_name().to_raw_bytes().ends_with(&*extension.to_raw_bytes()) { // Compare raw bytes; Both values were passed in from the host OS and so share encoding.
                continue; // Skip file
            }
        }

        let file_length = fs::metadata(file.path())?.len();
        file_size_map.entry(file_length).or_insert_with(Vec::new).push(file.path());
    }

    for files in file_size_map.into_values() {
        if files.len() < 2 { continue; }

        let mut file_hash_map = HashMap::new();

        for path in files {
            let mut hasher = Sha256::new();

            let mut file = fs::File::open(&path)?;
            io::copy(&mut file, &mut hasher)?;
            let hash = format!("{:X}", hasher.finalize());
            file_hash_map.entry(hash).or_insert_with(Vec::new).push(path);
            drop(file);
        }

        for (hash, same_hash_files) in file_hash_map {
            if same_hash_files.len() < 2 { continue; }

            if hash_only {
                let (first, next) = same_hash_files.split_first().unwrap(); // Keep first file, remove other files with same hash
                println!("{}", hash);
                println!("KEEP: {:?}", first.file_name().unwrap());
                for file in next {
                    println!("REMOVE: {:?}", file.file_name().unwrap());
                }
                println!();
                to_remove.extend_from_slice(next);
            } else {
                let (first, next) = same_hash_files.split_first().unwrap(); // Split to ensure we don't compare a file to itself
                let mut retained = vec![first];
                let mut to_remove_with_hash = Vec::new();
                'test_file_loop: for test_path in next {
                    for retained_file_path in &retained {
                        let mut test_file = fs::File::open(test_path)?;
                        let mut retained_file = fs::File::open(retained_file_path)?;

                        let mut test_buffer = [0u8; 512];
                        let mut retained_buffer = [0u8; 512];

                        loop {
                            let test_slice = read_buf_exact_or_eof(&mut test_file, &mut test_buffer)?;
                            let retained_slice = read_buf_exact_or_eof(&mut retained_file, &mut retained_buffer)?;
                            if test_slice.len() == 0 && retained_slice.len() == 0 {
                                to_remove.push(test_path.clone());
                                to_remove_with_hash.push(test_path);
                                continue 'test_file_loop;
                            } else if test_slice == retained_slice {
                                continue;
                            } else if test_slice != retained_slice {
                                retained.push(test_path);
                                continue 'test_file_loop;
                            }
                        }
                    }
                }
                println!("{}", hash);
                for file in retained {
                    println!("KEEP: {:?}", file.file_name().unwrap());
                }
                for file in to_remove_with_hash {
                    println!("REMOVE: {:?}", file.file_name().unwrap());
                }
                println!();
            }
        }
    }

    Ok(to_remove)
}