# PythonObfuscator

PythonObfuscator is a Python tool designed to obfuscate Python scripts for educational and experimental purposes. It utilizes AES encryption and randomization techniques to obscure code, potentially altering its readability and making it harder to understand. Please exercise caution when using it and be aware that it does not guarantee security.

## How to Use

To use PythonObfuscator:

1. Clone this repository to your local machine.
2. Install the required dependencies by running `pip install requirements.txt`.
3. Run the `obfuscate.py` script and follow the instructions.
4. Select the Python script you want to obfuscate.
5. Choose a strength value for obfuscation. Higher values can significantly increase resource usage.
6. The obfuscated code will be saved as `out-[timestamp].py` in the current directory.

## Disclaimer

This tool is provided for educational purposes only. It may alter code readability and does not guarantee security. Use at your own risk. No warranties are provided. Developers are not liable for any damages.

## Requirements

- Python 3.x
- pycryptodome

## Usage

```python
python obfuscate.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
