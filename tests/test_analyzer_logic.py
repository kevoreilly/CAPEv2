
import os
import hashlib
import tempfile
import shutil

# Mock config
class Config:
    id = 123
    timeout = 100

config = Config()

# Mock OS environment
os.environ["TMP"] = tempfile.mkdtemp()
os.environ["SystemRoot"] = tempfile.mkdtemp()
# Create Temp dir in SystemRoot
os.makedirs(os.path.join(os.environ["SystemRoot"], "Temp"), exist_ok=True)

# Logic to test
def check_completion():
    complete_folder = hashlib.md5(f"cape-{config.id}".encode()).hexdigest()
    complete_analysis_patterns = [os.path.join(os.environ["TMP"], complete_folder)]
    if "SystemRoot" in os.environ:
        complete_analysis_patterns.append(os.path.join(os.environ["SystemRoot"], "Temp", complete_folder))
    
    found = False
    for path in complete_analysis_patterns:
        if os.path.isdir(path):
            found = True
            print(f"Found at {path}")
            break
    return found

# Test Case 1: Folder in TMP
complete_folder = hashlib.md5(f"cape-{config.id}".encode()).hexdigest()
path1 = os.path.join(os.environ["TMP"], complete_folder)
os.makedirs(path1)
print(f"Testing TMP path: {path1}")
assert check_completion() == True
os.rmdir(path1)

# Test Case 2: Folder in SystemRoot/Temp
path2 = os.path.join(os.environ["SystemRoot"], "Temp", complete_folder)
os.makedirs(path2)
print(f"Testing SystemRoot path: {path2}")
assert check_completion() == True
os.rmdir(path2)

# Cleanup
shutil.rmtree(os.environ["TMP"])
shutil.rmtree(os.environ["SystemRoot"])

print("All tests passed")
