extern crate crypto;

use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use std::net::{ TcpListener, TcpStream };
use std::thread;
use std::fs::File;
use std::time::Duration;
use std::io::{ BufReader, BufRead, Read, Write, ErrorKind };

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }
    Ok(final_result)
}

fn main() {
    let mut file = BufReader::new(File::open("conf").expect("'conf' file not found."));
    let mut line = String::new();
    file.read_line(&mut line).expect("Can not read 'number_of_ports'");
    let number_of_ports = line.trim().parse::<u16>().expect("Unexpected 'number_of_ports'");
    let mut redirectors = Vec::new();
    for _ in 0..number_of_ports {
        let mut line = String::new();
        file.read_line(&mut line).expect("Can not read server/client");
        let is_server = line.trim().parse::<bool>().expect("Unexpected 'server/client'");
        let mut line = String::new();
        file.read_line(&mut line).expect("Can not read incomming 'ip:port'");
        let listener = TcpListener::bind(line.trim()).expect("can not connect to the address.");
        let mut line = String::new();
        file.read_line(&mut line).expect("Can not read outcomming 'ip:port'");
        let outstream = line.trim().to_string();
        let mut line = String::new();
        file.read_line(&mut line).expect("Can not read key");
        let mut key = Vec::new();
        for k in line.trim().split(',') {
            key.push(k.trim().parse::<u8>().expect("Unexpected key element"));
        }
        if key.len() < 32 {
            panic!("unexpected key length");
        }
        let mut line = String::new();
        file.read_line(&mut line).expect("Can not read iv");
        let mut iv = Vec::new();
        for i in line.trim().split(',') {
            iv.push(i.trim().parse::<u8>().expect("Unexpected iv element"));
        }
        if iv.len() < 16 {
            panic!("unexpected iv length");
        }
        redirectors.push(thread::spawn(move || {
            let mut threads = Vec::new();
            for instream in listener.incoming() {
                let mut instream = instream.unwrap();
                // instream.set_nonblocking(true).expect("set_nonblocking call failed");
                let outstream = outstream.clone();
                let key = key.clone();
                let iv = iv.clone();
                threads.push(thread::spawn( move || {
                    let mut outstream = TcpStream::connect(outstream).expect("can not connect to the outcomming address.");
                    // outstream.set_nonblocking(true).expect("set_nonblocking call failed");
                    // let ten_millis = Duration::from_millis(10);
                    loop {
                        println!("Reached3");
                        // thread::sleep(ten_millis);
                        let mut buf = vec![];
                        match instream.read_to_end(&mut buf) {
                            Ok(n) => {
                                if n > 0 {
                                    println!("Reached1");
                                    let data = if is_server {
                                        decrypt(&buf[0..n], &key, &iv).expect("can not encrypt")
                                    } else {
                                        encrypt(&buf[0..n], &key, &iv).expect("can not encrypt")
                                    };
                                    outstream.write(&data).expect("can not write");
                                }
                            },
                            Err(e) => {
                                if e.kind() != ErrorKind::WouldBlock {
                                    panic!("Unexecpected");
                                }
                            }
                        }
                        println!("Reached1");
                        // thread::sleep(ten_millis);
                        let mut buf = vec![];
                        match outstream.read_to_end(&mut buf) {
                            Ok(n) => {
                                if n > 0 {
                                    println!("Reached2");
                                    let data = if is_server {
                                        encrypt(&buf[0..n], &key, &iv).expect("can not encrypt")
                                    } else { 
                                        decrypt(&buf[0..n], &key, &iv).expect("can not encrypt")
                                    };
                                    instream.write(&data).expect("can not write");
                                }
                            },
                            Err(e) => {
                                if e.kind() != ErrorKind::WouldBlock {
                                    panic!("Unexecpected");
                                }
                            }
                        }
                    }
                }));
            }
            for t in threads {
                t.join().expect("can not join responders");
            }
        }));
    }
    for t in redirectors {
        t.join().expect("Redirectors have problem in joining.");
    }
}