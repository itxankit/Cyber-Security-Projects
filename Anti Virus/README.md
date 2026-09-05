# Basic Antivirus Simulation

This is a Python based antivirus simulation for an internship project. It shows how a signature scanner works using SHA-256 hashes, and also adds a few extra features like quarantine, restore, report generation, and file integrity checking.

It is only for learning. The sample files are harmless and the signatures are made for testing the project.

## Features

- Scans a file or full folder recursively
- Compares SHA-256 hashes with a local malware signature database
- Marks files as clean, suspicious, malicious, or error
- Finds simple suspicious cases like double extensions and script keywords
- Moves known malware matches to quarantine when selected
- Restores files from quarantine using their quarantine id
- Creates JSON scan reports, with optional CSV reports
- Builds a file baseline and later checks if files were added, removed, or changed
- Lets the user add new signatures from any file
- Has both command line commands and a simple menu mode

## How to Run

Open this folder in terminal and run:

    python antivirus.py scan samples

If Windows says python is not recognized, try:

    py antivirus.py scan samples

To scan and move known malware signature matches into quarantine:

    python antivirus.py scan samples --quarantine

To create a CSV report also:

    python antivirus.py scan samples --csv

To open the simple menu:

    python antivirus.py menu

## Baseline Checking

This part is for detecting modified or unauthorized files.

    python antivirus.py baseline samples

After changing, adding, or deleting a file:

    python antivirus.py check samples

## Quarantine

List quarantined files:

    python antivirus.py quarantine list

Restore a file:

    python antivirus.py quarantine restore QUARANTINE_ID

## Add a New Signature

If you want to mark a file as malware in the local database:

    python antivirus.py add-signature path/to/file.txt "My.Test.Signature"

The program hashes the file and stores the SHA-256 value in scanner_data/signatures.json.

## Project Flow

1. The scanner reads files in chunks so even bigger files can be scanned.
2. For each file, it calculates SHA-256 and MD5.
3. SHA-256 is checked against the signature database.
4. If the hash matches, the file is marked malicious.
5. If the hash does not match but the file looks risky, it is marked suspicious.
6. Reports are saved inside the reports folder.
7. When quarantine is used, the file is moved into quarantine and details are saved in an index.

## Folder Structure

    antivirus.py
    scanner_data/
      signatures.json
      baseline.json
    samples/
      clean_note.txt
      demo_malware.txt
      invoice.pdf.exe
    quarantine/
    reports/

baseline.json, reports, and quarantine index files are created while using the program.
