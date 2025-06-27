# directory brute force
A multithreaded Python-based Directory & File Discovery Tool for web servers. It helps identify hidden or sensitive files and directories by brute-forcing common paths using a customizable wordlist and extensions.



**Features**

Multi-threaded for fast scanning

Customizable wordlist and file extensions

Detects status codes like 200, 403, 301, etc.

Optional output to file

Configurable timeout and thread count

Helpful for reconnaissance and penetration testing



**Requirements**

Python 3.x

Install dependencies:

pip install -r requirements.txt



**Usage**

python main.py -u <target_url> -w <wordlist_file> [options]

Options: Flag Description

-u, --url Target URL (required)

-w, --wordlist Wordlist file path (required)

-t, --threads Number of threads (default: 10)

-s, --status Comma-separated list of status codes to show (default: 200,204,301,302,403)

-to, --timeout Request timeout in seconds (default: 5)

-e, --extensions Comma-separated extensions to append (e.g., php,asp)

-o, --output File to save the found results
