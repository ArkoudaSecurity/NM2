import nmap
 import scanner

 def map_website(website, port_range="1-65535", nm=None):
     ip_address = resolve_host(website)
     ip_address = scanner.resolve_host(website)

     if ip_address:
         print(f"Mapping website: {website} (IP: {ip_address})")
         open_ports = scan_ports(ip_address, port_range, nm)
         open_ports = scanner.scan_ports(ip_address, port_range, nm)

         if open_ports:
             print_open_ports_table(open_ports, nm)
             scanner.print_open_ports_table(open_ports, nm)
         else:
             print("No open ports found.")
     else:
 @@ -110,3 +27,4 @@ def main(target, port_range="1-65535"):
 if __name__ == "__main__":
     fire.Fire(main)




