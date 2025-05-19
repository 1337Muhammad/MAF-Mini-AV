import os
import subprocess
import hashlib
import zlib # for crc32 generation
from colorama import Fore, Style, init
init(autoreset=True)

# ---------------------------
# Configuration
# ---------------------------

# Path to 7-Zip executable (Windows) or '7z' command on Linux
SEVEN_ZIP_CMD = r"C:\Program Files\7-Zip\7z.exe"
# If using Linux, ensure '7z' is in PATH or adjust SEVEN_ZIP_CMD accordingly.

# Supported archive signatures (magic bytes)
# Added multiple RAR versions and additional formats if needed
MAGIC_HEADERS = {
    'zip':    [b"\x50\x4B\x03\x04"],                  # ZIP (PK..)
    'gzip':   [b"\x1F\x8B\x08"],                       # GZIP (CM=8)
    'bzip2':  [b"\x42\x5A\x68"],                       # BZIP2 (BZh)
    'xz':     [b"\xFD\x37\x7A\x58\x5A\x00\x00"],   # XZ
    'tar':    [b"ustar"],                                 # TAR ("ustar" at offset 257)
    '7z':     [b"\x37\x7A\xBC\xAF\x27\x1C"],        # 7z
    'rar':    [
        b"\x52\x61\x72\x21\x1A\x07\x00",           # RAR v4 signature
        b"\x52\x61\x72\x21\x1A\x07\x01\x00"        # RAR v5 signature
    ],
    'lzma':   [b"\x5D\x00\x00\x80\x00"],             # LZMA (optional)
}

# Malicous hashes db
MAL_HASHES = [
    '5D7F1A75B5E05A9B73EC7B2F1198B492FD30BC5C', #my_keylogger.py
    'f11fa868ac3dee1e5fbd985fe15ba6d34c7ec0abb47babe0d34a35514c49c86a',
    '8ace3486',
    '6b2f645881bed988d32c4f7241f3a8dd',
    '69d55495b7d59d72d32a07755a39197617927248edc3b72fb476f3ff3d05bd33c967928acf05df93897aedd58c75064694e6bc7a9b0a6aa618a5987ffadfed2c',
    '9fd20defd9b97add19d682d83e1a8ed5f20496c2d03110e15a6f7ba1c2e2999f0195f974fa0de8174edf2f09dce8c9f2',
]
MAL_HASHES = [element.lower() for element in MAL_HASHES]

# Compute the maximum signature length to know how many bytes to read
# We look at every signature in MAGIC_HEADERS and find the longest one.
# This ensures we read enough bytes from the file start to match any signature.
MAX_HEADER_LEN = max( # all those lengths are fed into max to pick the largest one
    len(sig)  # length of each individual magic signature
    for signatures in MAGIC_HEADERS.values()  # for each list of signatures = dict_values([[b'PK\x03\x04'], [b'BZh'], [b'ustar'],...])
    for sig in signatures  # for each signature in that list, in case that a signature has multiple sigs
)


# ---------------------------
# Function: detect_format
# ---------------------------

def detect_format(path):
    """
    Return archive format key by inspecting magic bytes only.
    No extension checks performed.
    """
    if not os.path.isfile(path):
        return None

    try:
        with open(path, 'rb') as f:
            # Read enough bytes to match any signature
            header = f.read(MAX_HEADER_LEN)

            # Check magic at file start
            for fmt, signatures in MAGIC_HEADERS.items():
                if fmt == 'tar': # as its sig offset is at 257
                    continue
                for sig in signatures:
                    if header.startswith(sig):
                        return fmt

            # TAR magic check at offset 257
            f.seek(257)
            if f.read(len(MAGIC_HEADERS['tar'][0])) == MAGIC_HEADERS['tar'][0]: # compare file.tar magic_header to the one on the list
                return 'tar'
    except Exception:
        return None

    return None

# ---------------------------
# Function: extract_with_7z
# ---------------------------

def extract_with_7z(archive, dest):
    """
    Always use 7z to extract the archive into dest directory.
    """
    if not os.path.exists(dest):
        os.makedirs(dest, exist_ok=True)
    cmd = [SEVEN_ZIP_CMD, 'x', archive, f'-o{dest}', '-y']
    try:
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #print(result.stdout.decode())
        return True
    except subprocess.CalledProcessError as err:
        print(f"Extraction failed for {archive}: {err.stderr.decode()}")
        return False

# ---------------------------
# Function: decompress_once
# ---------------------------

def decompress_once(path):
    """
    Decompress a single archive file detected via magic headers.
    """
    fmt = detect_format(path)
    if not fmt: # if is a file and not compressed just return it
        #print(f"Unknown format for {path}")
        return path

    base_name = os.path.splitext(os.path.basename(path))[0]
    out_dir = os.path.join(os.path.dirname(path), base_name)
    #print(f"Extracting {path} -> {out_dir} using 7z")
    return out_dir if extract_with_7z(path, out_dir) else None

# ---------------------------
# Function: recursive_decompress
# ---------------------------

def recursive_decompress(root):
    """
    Recursively find and extract archives under root using magic_headers detection.
    """
    processed = set()

    while True:
        archives = []
        #mapping every archive in given path
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                filepath = os.path.join(dirpath, name)
                if filepath in processed:
                    continue
                if detect_format(filepath):
                    archives.append(filepath)

        if not archives:
            #print(processed)
            return root
            #break
        
        for archive in archives:
            processed.add(archive)
            out = decompress_once(archive)
            #if out:
                #print(f"Scheduled nested decompress in: {out}")



# now we need to compute the hashes of all files under the extracted folder (What IF!!! it was not a compressed folder or it was a normal file or compressed file)
def hash_generator(path, algorithms=('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'crc')):
    """
    Compute specified hashes for all files under the given path.
    Handles both directories and individual files.
    """
    files_hashes = {}

    # If the path is a file, process it directly
    if os.path.isfile(path):
        files_to_process = [path]
    # If the path is a directory, traverse it recursively
    elif os.path.isdir(path):
        files_to_process = []
        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                files_to_process.append(os.path.join(dirpath, filename))
    else:
        print(f"Invalid path: {path}")
        return files_hashes

    for file_path in files_to_process:
        files_hashes[file_path] = {}

        for algo in algorithms:
            if algo != 'crc':
                hash_func = getattr(hashlib, algo)()
                try:
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hash_func.update(chunk)
                    files_hashes[file_path][algo] = hash_func.hexdigest()
                except Exception as e:
                    print(f"Error hashing {file_path} with {algo}: {e}")
            else:
                try:
                    with open(file_path, 'rb') as f:
                        crc = 0
                        for chunk in iter(lambda: f.read(4096), b""):
                            crc = zlib.crc32(chunk, crc)
                    files_hashes[file_path][algo] = format(crc & 0xFFFFFFFF, '08x')
                except Exception as e:
                    print(f"Error computing CRC32 for {file_path}: {e}")

    return files_hashes


def hash_compare(files_hashes, MAL_HASHES=MAL_HASHES):
    #print("\n\n\n\n\n\n\n")
    #print(files_hashes)
    for file_path, hashes in files_hashes.items():
        for algo, hash_value in hashes.items():
            if hash_value.lower() in MAL_HASHES:
                #print file path, algo, hash
                #print(file_path, algo, hash_value)
                #print(Fore.RED + Style.BRIGHT + f"{file_path} \n {algo}  {hash_value} \n\n")
                file_name = os.path.basename(file_path)
                print(
                    f"{os.path.dirname(file_path)}/"
                    + Fore.RED + Style.BRIGHT + f"{file_name}" + Style.RESET_ALL
                    + f"\n "
                    + Fore.YELLOW + Style.BRIGHT + f"{algo}" + Style.RESET_ALL
                    + "  "
                    + Fore.CYAN + Style.BRIGHT + f"{hash_value}" + Style.RESET_ALL
                    + "\n"
                )



# ---------------------------
# Entry Point
# ---------------------------

def main():

    #target = r"C:\Users\IEUser\Desktop\M.A.D"
    target = input("Enter the full path to scan: ").strip()
    if not os.path.exists(target):
        print("The specified path does not exist.")
        return

    folder = None

    # extraction process
    if os.path.isfile(target):
        #extracting the main target/path given by user if its an extracted file/dir 
        extracted = decompress_once(target) #extracted is the "new" main file/dir
        if not extracted:
            print("Extraction failed or not a supported archive.")
            return
        
        folder = recursive_decompress(extracted)
        # if os.path.isfile(extracted):
        #     folder = recursive_decompress(extracted)
    else:
        folder = recursive_decompress(target)

    if not folder:
        print("No files to process.")
        return

    folder_hashes = hash_generator(folder)
    hash_compare(folder_hashes)


    print("Completed.")

if __name__ == '__main__':
    main()
