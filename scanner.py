import socket
import random
import time

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # short timeout for faster scan
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False

def main():
    target = input("Enter target (IP or domain): ").strip()

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid target.")
        return

    print(f"\nScanning target: {target} ({target_ip})\n")

    ports = list(range(1, 10000))
    random.shuffle(ports)

    open_ports = []

    for port in ports:
        if scan_port(target_ip, port):
            print(f"[OPEN] Port {port}")
            open_ports.append(port)

    print("\nScan complete.")
    print(f"Open ports: {open_ports}")

if __name__ == "__main__":
    main()
