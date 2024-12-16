import os
import sys
import subprocess
import tempfile
import re
import pyfiglet
import argparse

def print_banner():
    main_banner = pyfiglet.figlet_format("Privia Security")
    sub_banner = pyfiglet.figlet_format("Key Detector")
    print(main_banner)
    print(sub_banner)

def decompile_apk(apk_path, output_dir):
    """\033[33m[!] Decompile the APK \033[0m"""
    try:
        subprocess.run(["apktool", "-q", "d", "-f", "-o", output_dir, apk_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"\033[31m[-] Error during APK decompilation: {e}\033[0m")
        sys.exit(1)

def is_variable_definition(line, keyword):
    """Check if a line contains a variable definition with the given keyword."""
    variable_pattern = re.compile(
        rf"\b(?:[a-zA-Z_]\w*\s+)?\w*{re.escape(keyword)}\w*\b\s*=\s*.+",
        re.IGNORECASE
    )
    return bool(variable_pattern.search(line))

def search_keywords_in_files(directory, keywords):
    """Search for multiple keywords in all files within a directory and check if they are variables."""
    matches = {keyword: [] for keyword in keywords}
    total_files = sum([len(files) for _, _, files in os.walk(directory)])
    files_processed = 0
    reported_lines = set()

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        for keyword in keywords:
                            if (file_path, line_no) not in reported_lines:  
                                if is_variable_definition(line, keyword):
                                    matches[keyword].append((file_path, line_no, line.strip()))
                                    print(f"\033[32m[+] File Found:\033[0m {file_path}, Line: {line_no}, \033[32;1m [+] Match Value: {line.strip()}\033[0m", flush=True)
                                    reported_lines.add((file_path, line_no))  
            except Exception as e:
                print(f"Could not read {file_path}: {e}")

            files_processed += 1
            print(f"Searching files: {files_processed}/{total_files} files processed...", end="\r", flush=True)

    return matches

def load_keywords_from_file(wordlist_path):
    """Load keywords from a wordlist file."""
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            keywords = [line.strip() for line in f.readlines() if line.strip()]
        return keywords
    except Exception as e:
        print(f"Error loading wordlist file: {e}")
        sys.exit(1)

def extract_and_search_apk(apk_path, keywords):
    """Extract APK contents and search for multiple keywords as variables."""
    with tempfile.TemporaryDirectory() as temp_dir:
        print("Decompiling the APK...")
        decompiled_dir = os.path.join(temp_dir, "decompiled")
        decompile_apk(apk_path, decompiled_dir)

        print(f"Starting to Search for keywords")
        matches = search_keywords_in_files(decompiled_dir, keywords)
        
        matches_found = any(len(match) > 0 for match in matches.values())
        
        if not matches_found:
            print("\033[31m[-] No matches found.\033[0m")

def main():
    parser = argparse.ArgumentParser(
        description="APK Key Detector - A tool to detect keywords in APK files, either by direct input or using a wordlist.",
        usage="python %(prog)s apk_file \"keyword1,keyword2\" or python %(prog)s apk_file -w wordlist.txt"
    )
    parser.add_argument("apk_file", help="Path to the APK file to be scanned.")
    parser.add_argument(
        "-w",
        "--wordlist",
        help="Path to a wordlist file containing keywords to search for.",
        default=None,
    )
    parser.add_argument(
        "keywords",
        nargs="?",
        help="Comma-separated list of keywords to search directly (used when --wordlist is not provided).",
        default=None,
    )

    args = parser.parse_args()

    if not os.path.isfile(args.apk_file):
        print(f"File not found: {args.apk_file}")
        sys.exit(1)

    print_banner()

    if args.wordlist:
        keywords = load_keywords_from_file(args.wordlist)
        print(f"{len(keywords)} keywords loaded from wordlist.")
    elif args.keywords:
        keywords = args.keywords.split(',')
    else:
        print("Error: You must provide either a wordlist or keywords.")
        sys.exit(1)

    extract_and_search_apk(args.apk_file, keywords)

if __name__ == "__main__":
    main()
