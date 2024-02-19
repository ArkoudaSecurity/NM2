import nmap as nm
import socket


def resolve_host(hostname):
    # Resolves the IP address of a given hostname.
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        print(f"Error resolving hostname {hostname}: {e}")
        return None

def scan_ports(target, port_range, nm):
    # Scans ports on a target using Nmap.
    nm.scan(target, arguments=f'-p {port_range} -T4 -O')  # Added OS detection flag '-O'

    open_ports = []
    for host in nm.all_hosts():
        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                if nm[host]['tcp'][port]['state'] == 'open':
                    open_ports.append((host, 'tcp', port))

    results = open_ports
    return results

def get_service_info(host, proto, port, nm):
    # Retrieves service information for a given host, protocol, and port.
    try:
        return nm[host][proto][port]
    except KeyError:
        return {"name": "Unknown Service", "extrainfo": "Unknown Risk"}

def assess_risk(extrainfo):
    # Assess the risk level based on extra information provided for a service.
    if "high" in extrainfo.lower():
        return "High Risk"
    elif "medium" in extrainfo.lower():
        return "Medium Risk"
    elif "low" in extrainfo.lower():
        return "Low Risk"
    else:
        return "Unknown Risk"

def print_open_ports_table(open_ports, nm):
    # Prints a table of open ports along with service and risk level information.
    print("Open Ports Table:")
    print("{:<15} {:<15} {:<10} {:<20} {:<40}".format("Host", "Protocol", "Port", "Service", "Risk Level"))
    print("-" * 100)

    for host, proto, port in open_ports:
        service_info = get_service_info(host, proto, port, nm)
        service_name = service_info.get("name", "Unknown Service")
        service_risk = service_info.get("extrainfo", "Unknown Risk")

        risk_level = assess_risk(service_risk)

        print("{:<15} {:<15} {:<10} {:<20} {:<40}".format(host, proto, port, service_name, risk_level))

    # Provide reasons for securing the open ports
    print("\nSecurity Considerations:")
    for host, proto, port in open_ports:
        print_security_reasons(port)

    # Display OS detection results grouped by IP address
    print("\nOS Detection:")
    for host in nm.all_hosts():
        if 'osmatch' in nm[host]:
            os_detections = ", ".join(f"{match['name']} (Accuracy: {match['accuracy']})" for match in nm[host]['osmatch'])
            print(f"{host}: {os_detections}")

def print_security_reasons(port):
    # Prints security considerations for open ports.
    security_reasons = {
        21: "FTP (File Transfer Protocol) - Unencrypted file transfer. Use SFTP or FTPS for secure file transfer.",
        22: "SSH (Secure Shell) - Secure remote access. Limit access to authorized users.",
        23: "Telnet - Unencrypted remote access. Avoid using Telnet; use SSH instead.",
        25: "SMTP (Simple Mail Transfer Protocol) - Email communication. Secure email server to prevent abuse.",
        80: "HTTP - Unencrypted web traffic. Consider using HTTPS to encrypt web communication.",
        443: "HTTPS - Encrypted web traffic. Ensure secure communication for sensitive data.",
        3306: "MySQL - Database communication. Restrict access and use strong authentication.",
        3389: "RDP (Remote Desktop Protocol) - Remote desktop access. Secure with strong passwords and limit access."
        # Add more reasons for other ports as needed
    }

    if port in security_reasons:
        print(security_reasons[port])
    else:
        print(f"Security reasons for port {port} are not provided.")


