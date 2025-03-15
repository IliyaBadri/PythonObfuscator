import collections
import base64
import random
import typing
import time
import sys
import os

class DataManager:
    unobfuscated_block = collections.deque()
    obfuscated_block = collections.deque()

    @staticmethod
    def load_file_into_unobfuscated_block(file_path: str):
        """Loads a file into the unobfuscated block."""
        CHUNK_SIZE = 1024
        try:
            file = open(file_path, "rb")
            chunk = file.read(CHUNK_SIZE)
            while chunk != b"":
                DataManager.unobfuscated_block.extend(chunk)
                chunk = file.read(CHUNK_SIZE)
        except:
            print(f"\n[-] There was an error while reading the input file ({file_path}) and writing it to the unobfuscated block.")
            print("[-] Terminating.")
            sys.exit(1)
        finally:
            file.close()

    @staticmethod
    def pop_from_unobfuscated_block() -> typing.Optional[int]:
        """Return a byte from the start of the unobfuscated block and removes that byte from it."""
        if DataManager.is_unobfuscated_block_empty():
            return None
        return DataManager.unobfuscated_block.popleft()

    @staticmethod
    def get_unobfuscated_block_length() -> int:
        """Get the byte count of the unobfuscated block"""
        return len(DataManager.unobfuscated_block)

    @staticmethod
    def is_unobfuscated_block_empty() -> bool:
        """Check if the unobfuscated block is empty"""
        return len(DataManager.unobfuscated_block) <= 0

    @staticmethod
    def clear_obfuscated_block():
        """Clear all bytes in the obfuscated block"""
        DataManager.obfuscated_block.clear()

    @staticmethod
    def write_chunk_to_obfuscated_block(chunk: bytearray):
        """Write an array of bytes to the end of the obfuscated block"""
        DataManager.obfuscated_block.extend(chunk)

    @staticmethod
    def move_obfuscated_block_to_unobfuscated_block():
        """Moves all the content inside the obfuscated block to the unobfuscated block (With minimal memory usage)"""
        DataManager.unobfuscated_block.clear()
        for _ in range(len(DataManager.obfuscated_block)):
            if len(DataManager.obfuscated_block) == 0:
                break
            DataManager.unobfuscated_block.append(DataManager.obfuscated_block.popleft())

    @staticmethod
    def write_obfuscated_block_to_file(file_path: str):
        """Write the content inside the obfuscated block to a file"""
        try:
            file = open(file_path, "wb")
            for _ in range(len(DataManager.obfuscated_block)):
                if(len(DataManager.obfuscated_block) == 0):
                    break
                file.write(bytes([DataManager.obfuscated_block.popleft()])) 
        except:
            print(f"\n[-] There was an error while writing the unobfuscated block to the file ({file_path}).")
            print("[-] Terminating.")
            sys.exit(1)
        finally:
            file.close()

class Cryptography:
    @staticmethod
    def get_encryption_key(length: int = 16) -> str:
        """Get a random encryption key in plaintext (base64 encoded) for XOR encryption"""
        key_bytes = bytearray()
        for _ in range(length):
            key_bytes.append(random.getrandbits(8))
        key = base64.b64encode(key_bytes).decode("utf-8")
        return key

    @staticmethod
    def get_variable_name(length: int = 32) -> str:
        """Get a random variable name suited for python standards"""
        characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        variable_name = ""
        for _ in range(length):
            character_index = random.randint(0, len(characters) - 1)
            variable_name += characters[character_index]
        return variable_name

    @staticmethod
    def get_random_variable_name_list(count: int, length: int = 32):
        """Get a list of unique variable names"""
        variable_names = []
        while len(variable_names) < count:
            variable_name = Cryptography.get_variable_name(length)
            if variable_name in variable_names:
                continue
            variable_names.append(variable_name)
        return variable_names

class Obfuscator:
    @staticmethod 
    def obfuscate_current_layer():
        """Obfuscate the current layer of code. This will obfuscate the data in unobfuscated block and will write it to the obfuscated block"""
        DataManager.clear_obfuscated_block()

        key = Cryptography.get_encryption_key()
        key_bytes = base64.b64decode(key.encode("utf-8"))
        key_length = len(key_bytes)

        variable_names = Cryptography.get_random_variable_name_list(5)

        code_block_1 = f"""import base64
{variable_names[0]} = base64.b64decode("{key}".encode("utf-8"))
{variable_names[1]} = \""""

        code_block_1_bytes = code_block_1.encode("utf-8")
        DataManager.write_chunk_to_obfuscated_block(code_block_1_bytes)

        print(" | Encrypting unobfuscated block into obfuscated block ", end="", flush=True)
        current_xored_chunk = bytearray()
        for i in range(DataManager.get_unobfuscated_block_length()):
            if(DataManager.is_unobfuscated_block_empty()):
                break
            current_unobfuscated_byte = DataManager.pop_from_unobfuscated_block()
            current_xored_chunk.append(current_unobfuscated_byte ^ key_bytes[i % key_length])

            if DataManager.is_unobfuscated_block_empty() or len(current_xored_chunk) == 3:
                base64_chunk = base64.b64encode(current_xored_chunk)
                DataManager.write_chunk_to_obfuscated_block(base64_chunk)
                current_xored_chunk.clear()
        
        print("(COMPLETE)", flush=True)
        
        code_block_2 = f"""\"
if __name__ == "__main__":
    {variable_names[2]} = base64.b64decode({variable_names[1]}.encode("utf-8"))
    {variable_names[3]} = bytearray()
    for {variable_names[4]} in range(len({variable_names[2]})):
        {variable_names[3]}.append({variable_names[2]}[{variable_names[4]}]^{variable_names[0]}[{variable_names[4]} % len({variable_names[0]})])
    exec({variable_names[3]}.decode("utf-8"))
"""
        code_block_2_bytes = code_block_2.encode("utf-8")
        DataManager.write_chunk_to_obfuscated_block(code_block_2_bytes)

    @staticmethod
    def obfuscate_in_layers(layer_count: int):
        """Create many obfuscation layer on top of each other"""
        for i in range(layer_count):
            print(f"[+] Obfuscating layer {i + 1} / {layer_count}:")
           
            Obfuscator.obfuscate_current_layer()
            if i == layer_count - 1:
                break

            print(" | Moving obfuscated block to unobfuscated block ", end="", flush=True)
            DataManager.move_obfuscated_block_to_unobfuscated_block()
            print("(COMPLETE)", flush=True)

def main():
    print("[+] Python Obfuscator v1.1.0")
    print("[+] This is an open-source free tool developed by IliyaBadri.")

    print("\n[+] In order for this tool to work correctly, your python project must be all in one single python script (.py) file.")
    entered_file_path = input("\n[>] Please enter the path to your python script file you wish to obfuscate: ")

    input_file_path = os.path.abspath(entered_file_path)
    
    if not os.path.isfile(input_file_path):
        print(f"\n[-] ({input_file_path}) is not a file.")
        print("[-] Terminating.")
        sys.exit(1)
        return

    if not os.access(input_file_path, os.R_OK):
        print(f"\n[-] Couldn't open the file at ({input_file_path}) in read mode.")
        print("[-] Terminating.")
        sys.exit(1)
        return
    print(f" | ({input_file_path}) will be obfuscated.")

    print("\n[+] You must now provide the layer count for obfuscation.")
    print(" | You can enter any number above 0. This number will correspond to how many layers of obfuscation, your code will be wrapped in.")
    print(" | Strength values above a certain level can be resource intensive. Please make sure you have a decent amount of ram available.")
    print(" | Any value above 10 is considered overkill.")
    entered_obfuscation_layer_count = input("[>] Obfuscation layer count: ")

    if not entered_obfuscation_layer_count.isdigit():
        print("\n[-] Obfuscation layer count must be a number.")
        print("[-] Terminating.")
        sys.exit(1)
        return

    obfuscation_layer_count = int(entered_obfuscation_layer_count)

    if obfuscation_layer_count <= 0:
        print("\n[-] Obfuscation layer count must be a (non-zero) positive number.")
        print("[-] Terminating.")
        sys.exit(1)
        return

    print("\n[+] Loading input file into unobfuscated block ", end="", flush=True)
    DataManager.load_file_into_unobfuscated_block(input_file_path)
    print("(COMPLETE)\n", flush=True)

    Obfuscator.obfuscate_in_layers(obfuscation_layer_count)

    print("[+] Obfuscation operation is complete.")

    current_timestamp = time.time()
    output_file_name = f"out-{str(int(current_timestamp))}.py"
    output_file_path = os.path.abspath(f"./{output_file_name}")
    output_file_directory = os.path.dirname(output_file_path)

    print(f"\n[+] Saving output to ({output_file_path}) ", end="", flush=True)

    if not os.access(output_file_directory, os.W_OK):
        print(f"\n[-] Couldn't create the file at ({output_file_path}).")
        print("[-] Terminating.")
        sys.exit(1)
        return

    DataManager.write_obfuscated_block_to_file(output_file_path)
    print(f"(COMPLETE)", flush=True)

if __name__ == '__main__':
    main()
    sys.exit(0)
    
