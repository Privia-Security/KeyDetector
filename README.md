# KeyDetector

KeyDetector is a tool for decompiling Android APK files, searching for specified keywords, and reporting only variable definitions.

## Features
- Decompiles APK files using `apktool`.
- Searches for multiple specified keywords across all files.
- Reports only variable definitions.
- Outputs results in a user-friendly format.

## Requirements
- Python 3.7 or higher
- `apktool` (required for APK decompilation)


## Usage
```bash
python key_detector.py <apk_file_path> <keyword1,keyword2,...>
```

### Example:
```bash
python key_detector.py sample.apk key1,key2
```

This command decompiles the `sample.apk` file and checks if `key1`, `key2`, etc., are defined as variables.

### Output:
- File name where the keyword is found
- Line number
- The corresponding code line

### Note:
You can search for multiple keywords by separating them with a comma (`,`).
