import nmap
import scanner
import fire
import csv

def map_website(website, port_range="1-65535", nm=None):
    ip_address = scanner.resolve_host(website)
    scan_results = None

    if ip_address:
        print(f"Mapping website: {website} (IP: {ip_address})")
        open_ports = scanner.scan_ports(ip_address, port_range, nm)
        
        if open_ports:
            scanner.print_open_ports_table(open_ports, nm)
            # Store the scan results
            scan_results = open_ports
        else:
            print("No open ports found.")
    else:
        print("Failed to resolve the IP address for the website.")

    return scan_results


import csv

def export_results(results, export_file):
    if results:
        with open(export_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Assuming the first row contains headers, so we skip writing headers if file already exists
            if csvfile.tell() == 0:
                writer.writerow(['Host','Protocol', 'Port'])
            writer.writerows(results)
        print(f"Scan results appended to {export_file}.")
    else:
        print("No scan results to export.")




def main(target, port_range="1-65535", export_file="scan_results.csv"):
    if target.startswith("http://") or target.startswith("https://"):
        # Remove the protocol part from the URL
        target = target.split("://")[1]

    nm = nmap.PortScanner()
    results = map_website(target, port_range, nm)
    if results:
        export_results(results, export_file)
    else:
        print("No scan results to export.")

if __name__ == "__main__":
    fire.Fire(main)




