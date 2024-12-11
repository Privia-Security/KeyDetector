import os
import sys
import subprocess
import tempfile
import re
import pyfiglet

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
    """\033[33m[!] Check if a line contains a variable definition with the given keyword.\033[0m"""
    
    variable_pattern = re.compile(rf"\b\w*{re.escape(keyword)}\w*\b\s*=.*", re.IGNORECASE)
    return bool(variable_pattern.search(line))

def search_keywords_in_files(directory, keywords):
    """\033[33m[!] Search for multiple keywords in all files within a directory and check if they are variables.\033[0m"""
    matches = {keyword: [] for keyword in keywords}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, start=1):
                        for keyword in keywords:
                            if is_variable_definition(line, keyword):
                                matches[keyword].append((file_path, line_no, line.strip()))
            except Exception as e:
                print(f"\033[31mCould not read {file_path}: {e}\033[0m")
    return matches

def extract_and_search_apk(apk_path, keywords):
    """\033[33m [!] Extract APK contents and search for multiple keywords as variables.\033[0m"""
    with tempfile.TemporaryDirectory() as temp_dir:

        print("\033[33m [!] Decompiling the APK...\033[0m")
        decompiled_dir = os.path.join(temp_dir, "decompiled")
        decompile_apk(apk_path, decompiled_dir)

        print(f"\033[33m[!] Searching for keywords as variables: {', '.join(keywords)}...\033[0m")
        matches = search_keywords_in_files(decompiled_dir, keywords)

        for keyword, occurrences in matches.items():
            print(f"\n\033[32m[+] Results for keyword '{keyword}':\033[0m")
            if occurrences:
                for match in occurrences:
                    print(f"\033[32m[+] File Found:\033[0m {match[0]}, Line: {match[1]}, \033[32;1m [+] Match Value: {match[2]}\033[0m")
            else:
                print("\033[31m[-] No matches found.\033[0m")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python apk_reverse_search.py <apk_file_path> <comma_separated_keywords>")
        sys.exit(1)

    apk_file_path = sys.argv[1]
    keywords = sys.argv[2].split(',')

    if not os.path.isfile(apk_file_path):
        print(f"File not found: {apk_file_path}")
        sys.exit(1)

    print_banner()
    extract_and_search_apk(apk_file_path, keywords)
