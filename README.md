# PythonObfuscator

## Overview

This is an open-source Python obfuscation tool. It transforms Python scripts into obfuscated versions by applying multiple layers of XOR-based encoding with dynamically generated keys. The obfuscator does **not require any external dependencies**, making it lightweight and easy to use.

## Features

-   No external dependencies required
-   Multi-layer obfuscation for enhanced security and protection against automated de-obfuscation tools
-   XOR encryption with base64 encoding
-   Dynamically generated variable names and encryption keys
-   File I/O operations with error handling

## How It Works

1.  Reads the input Python script.
2.  Encrypts the script content using XOR encryption with a randomly generated key.
3.  Encodes the encrypted content in base64 format.
4.  Wraps the encoded content in a self-decoding Python script.
5.  Repeats the process for the specified number of layers.
6.  Outputs an obfuscated Python script that self-deciphers when executed.

## Installation

No installation is required! The script runs on any system with Python installed (Python 3 recommended).

## Usage

Run the script and follow the prompts:

```bash
python obfuscator.py
```

### Steps

1.  Enter the path to your Python script.
2.  Choose the number of obfuscation layers (recommended: 1-10).
3.  The obfuscated script is saved in the current directory as `out-<timestamp>.py`.

## Notes

-   This tool is intended for educational purposes and lightweight obfuscation.
-   While obfuscation makes reverse-engineering harder, it does **not** provide true security and is not bullet-proof.
-   Excessive layering may impact execution performance of the original script. (It takes some time for the layers to be unwrapped one by one during execution)

## License
This project is open-source and free to use and is licensed under the MIT license.

