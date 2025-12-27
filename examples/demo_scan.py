# demo_scan.py
from src.scanner import Scanner

def main():
    # Minimal demo: safe target
    scanner = Scanner(base_url="https://example.com", scope_paths=["/"])
    scanner.run(max_pages=5)

if __name__ == "__main__":
    main()
