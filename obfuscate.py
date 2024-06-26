from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import time
import sys
import re
import os

class Obfuscator:
    def __init__(self) -> None:
        pass

    def GetObfuscatedVariableName(self) -> str:
        randomBase64String = base64.b64encode(get_random_bytes(32)).decode('utf-8')
        formattedVariableCharacters = re.findall(r'[a-zA-Z]+', randomBase64String)
        variableName = "".join(formattedVariableCharacters)
        return variableName
    
    def Obfuscate(self, code: str) -> str:
        codeLength = len(code)
        spacesNeeded = 16 - (codeLength % 16)
        paddedCode = code + ' ' * spacesNeeded

        iv = get_random_bytes(16)
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            encryptedCode = cipher.encrypt(paddedCode.encode('utf-8'))
        except:
            print("Error: There was an error while encrypting the code")
            sys.exit(1)
                  

        encodedCode = base64.b64encode(encryptedCode).decode('utf-8')
        encodedKey = base64.b64encode(key).decode('utf-8')
        encodedIv = base64.b64encode(iv).decode('utf-8')

        encodedCodeVariableName = self.GetObfuscatedVariableName()
        encodedKeyVariableName = self.GetObfuscatedVariableName()
        encodedIvVariableName = self.GetObfuscatedVariableName()

        keyVariableName = self.GetObfuscatedVariableName()
        ivVariableName = self.GetObfuscatedVariableName()
        encryptedCodeVariableName = self.GetObfuscatedVariableName()
        cipherVariableName = self.GetObfuscatedVariableName()
        decryptedCodeVariableName = self.GetObfuscatedVariableName()

        obfuscatedCode = f"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

{encodedCodeVariableName} = '{encodedCode}'
{encodedKeyVariableName} = '{encodedKey}'
{encodedIvVariableName} = '{encodedIv}'

{encryptedCodeVariableName} = base64.b64decode({encodedCodeVariableName})
{keyVariableName} = base64.b64decode({encodedKeyVariableName})
{ivVariableName} = base64.b64decode({encodedIvVariableName})

{cipherVariableName} = AES.new({keyVariableName}, AES.MODE_CBC, {ivVariableName})
{decryptedCodeVariableName} = {cipherVariableName}.decrypt({encryptedCodeVariableName}).rstrip()
exec({decryptedCodeVariableName}.decode('utf-8'))
        """

        return obfuscatedCode

    def MultilayerObfuscate(self, code: str, layers: int):

        currentCode = code

        for i in range(layers):
            currentCode = self.Obfuscate(currentCode)
            layerStatus = f"Layer ({str(i+1)} / {str(layers)}) {str(round(((i + 1) / layers) * 100))}%"
            print(layerStatus)

        return currentCode


class DiskManager:
    def __init__(self) -> None:
        pass

    def GetFilesInDirectory(self, directory) -> list:
        files = []
        for file in os.listdir(directory):
            filePath = os.path.join(directory, file)
            if os.path.isfile(filePath):
                files.append(file)
        return files
    

class OperationManager:
    version = "1.0.1"
    author = "IliyaBadri"

    def __init__(self) -> None:
        pass

    def SendStart(self) -> None:
        print(f"Python Obfuscator v{self.version}")
        print(f"This is an open-source free tool developed by {self.author}.")
        disclaimer = """This tool is for educational purposes only. Exercise caution when using it. It may alter code readability and does not guarantee security. Use at your own risk. No warranties provided. Developers are not liable for any damages."""
        print(f"Disclaimer:\n{disclaimer}")

    def GetStrength(self) -> int:
        strengthGuide = """
Please provide a strength value number for obfuscation.
You can enter any number above 0.
Note: Strength values above 35 can be really resource intensive. please make sure you have a decent amount of ram available.
        """
        print(strengthGuide)
        strengthString = input("Please enter an obfuscation strength value: ")
    
        if not strengthString.isdigit():
            print("Error: Your strength value was not valid.")
            return self.GetStrength(self)
        
        strength = int(strengthString)

        if strength < 1:
            print("Error: Your strength value must be 1 or more than 1.")
            return self.GetStrength(self)
        
        return strength

    def GetInputFile(self) -> str:
        currentPath = os.getcwd()
        diskManager = DiskManager()
        files = diskManager.GetFilesInDirectory(currentPath)
        filesStringList = ""

        fileCount = 0
        for file in files:
            filesStringList += f"{str(fileCount)}) {file}\n"
            fileCount += 1

        promptString = f"""
List of file(s) inside {os.path.abspath(currentPath)}
--- total {str(len(files))} file(s) ---
{filesStringList}
--- indexes from 0 to {str(fileCount)} ---
        """

        print(promptString)

        selectedIndexString = input("Please enter the index of the file you want to obfuscate: ")

        if not selectedIndexString.isdigit():
            print("Error: Please enter a number as the input.")
            return self.GetInputFile()
        
        selectedIndex = int(selectedIndexString)

        if 0 > selectedIndex or selectedIndex > fileCount:
            print(f"Error: Please enter a number between 0 and {str(fileCount)}.")
            return self.GetInputFile()

        selectedFile = files[selectedIndex]

        return os.path.abspath(os.path.join(currentPath, selectedFile))

    def SaveOutput(self, output: str) -> None:
        currentTimestamp = time.time()
        fileName = f"out-{str(int(currentTimestamp))}.py"
        print(f"Saving as {fileName} . . .")

        try:
            theoutputfile = open(file=fileName, mode="w")
            theoutputfile.write(output)
            theoutputfile.close()

            return
        except:
            print("Error: we couldn't save the output to a file")
            sys.exit(1)
        


if __name__ == '__main__':
    operationManager = OperationManager()
    operationManager.SendStart()

    originalFilePath = operationManager.GetInputFile()
    try:
        originalFile = open(originalFilePath, "r")
        originalScript = originalFile.read()
    except:
        print("Error: couldn't open the selected file.")
        sys.exit(1)

    strength = operationManager.GetStrength()
    
    obfuscator = Obfuscator()

    obfuscatedCode = obfuscator.MultilayerObfuscate(originalScript, strength)

    operationManager.SaveOutput(obfuscatedCode)

    sys.exit(0)
    
