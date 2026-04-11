# security_config.py
# Author: Adith (copied for integration)
# Purpose: Security configuration and input functions

import re
import bleach

ALLOWED_EXTENSIONS = {"log", "txt"}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


def sanitise_ip(ip_string):
    """
    Validates that a string looks like a real IP address.
    Returns the IP if valid, returns 'invalid' if not.
    This prevents attackers from injecting code through the IP field.
    """
    if not ip_string:
        return "unknown"

    pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    if pattern.match(ip_string):
        parts = ip_string.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return ip_string

    return "invalid"


def sanitise_text(text):
    """
    Cleans a text string by removing any HTML tags.
    Uses the bleach library to strip dangerous HTML characters.
    This prevents Cross Site Scripting (XSS) attacks.
    XSS is when an attacker injects malicious scripts into a webpage.
    """
    if not text:
        return ""

    cleaned = bleach.clean(str(text), tags=[], strip=True)

    return cleaned[:1000]


def sanitise_filename(filename):
    """
    Cleans an uploaded filename to prevent path traversal attacks.
    Path traversal is when an attacker uses '../' to access other folders.
    Example attack: filename = '../../etc/passwd'
    """
    if not filename:
        return ""

    filename = filename.replace("/", "").replace("\\", "").replace("..", "")

    pattern = re.compile(r'[^a-zA-Z0-9._-]')
    cleaned = pattern.sub("", filename)

    return cleaned


def is_allowed_file(filename):
    """
    Checks if an uploaded file has an allowed extension.
    Returns True if allowed, False if not.
    """
    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS


def is_valid_file_size(file_size_bytes):
    """
    Checks if an uploaded file is within the allowed size limit.
    Returns True if size is acceptable, False if too large.
    """
    return file_size_bytes <= MAX_FILE_SIZE_BYTES


def validate_log_type(log_type):
    """
    Checks that the log type submitted by the user is one we expect.
    Prevents attackers from passing unexpected values.
    """
    allowed_types = ["ssh", "firewall", "apache"]
    return log_type in allowed_types


if __name__ == "__main__":
    print("=== Testing Security Config ===\n")

    print("IP Tests:")
    print(sanitise_ip("192.168.1.1"))       
    print(sanitise_ip("999.999.999.999"))   
    print(sanitise_ip("<script>alert(1)"))  

    print("\nText Tests:")
    print(sanitise_text("<script>alert('xss')</script>")) 
    print(sanitise_text("Normal log message"))             

    print("\nFilename Tests:")
    print(sanitise_filename("../../etc/passwd"))   
    print(sanitise_filename("auth.log"))            

    print("\nFile Type Tests:")
    print(is_allowed_file("auth.log"))    
    print(is_allowed_file("virus.exe"))   