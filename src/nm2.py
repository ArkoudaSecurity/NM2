import fire
import nmap
import scanner

def map_website(website, port_range="1-65535", nm=None):
    ip_address = scanner.resolve_host(website)

    if ip_address:
        print(f"Mapping website: {website} (IP: {ip_address})")
        open_ports = scanner.scan_ports(ip_address, port_range, nm)
        
        if open_ports:
            scanner.print_open_ports_table(open_ports, nm)
        else:
            print("No open ports found.")
    else:
        print("Failed to resolve the IP address for the website.")

def main(target, port_range="1-65535"):
    if target.startswith("http://") or target.startswith("https://"):
        # Remove the protocol part from the URL
        target = target.split("://")[1]

    nm = nmap.PortScanner()
    map_website(target, port_range, nm)

if __name__ == "__main__":
    fire.Fire(main)


