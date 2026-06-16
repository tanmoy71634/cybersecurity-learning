import socket

# Common ports and their services
SERVICES = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP"
}


def scan_port(target, port):
    """
    Scan a single TCP port.
    Returns True if open, False otherwise.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        result = s.connect_ex((target, port))
        s.close()

        return result == 0

    except socket.gaierror:
        print("Error: Invalid hostname or IP address.")
        return None

    except Exception as e:
        print(f"Error: {e}")
        return None


def main():
    target = input("Enter target IP or hostname: ").strip()

    ports = list(SERVICES.keys())

    print(f"\nScanning {target}...\n")

    open_ports = 0

    for port in ports:
        status = scan_port(target, port)

        if status is None:
            return

        service_name = SERVICES.get(port, "Unknown")

        if status:
            print(f"{port:<5} OPEN   ({service_name})")
            open_ports += 1
        else:
            print(f"{port:<5} CLOSED ({service_name})")

    print("\nScan Complete")
    print(f"Total Ports Scanned: {len(ports)}")
    print(f"Open Ports Found: {open_ports}")


if __name__ == "__main__":
    main()

