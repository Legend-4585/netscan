import socket
from scapy.all import ARP, Ether, srp
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def network_scanner():
    # Get network interface information
    ip_range = input("Enter IP range or CIDR (e.g., 192.168.1.0/24): ")
    
    # ARP Scan for host discovery
    print("\n[+] Scanning for active hosts...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
    
    hosts = []
    for sent, received in result:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    print("\nActive Hosts:")
    for host in hosts:
        print(f"IP: {host['ip']}\tMAC: {host['mac']}")
    
    return hosts

def port_scanner(ip, ports):
    print(f"\nScanning {ip}...")
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    service = socket.getservbyport(port)
                    open_ports.append((port, service))
                    print(f"Port {port} ({service}) is open")
        except:
            pass
    return (ip, open_ports)

def main():
    hosts = network_scanner()
    
    # Port scanning options
    ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389]
    print("\n[+] Starting port scan...")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = []
        for host in hosts:
            future = executor.submit(port_scanner, host['ip'], ports)
            results.append(future)
        
        print("\nScan Results:")
        for result in results:
            ip, open_ports = result.result()
            if open_ports:
                print(f"\n{ip} has open ports:")
                for port, service in open_ports:
                    print(f"- {port} ({service})")

if __name__ == "__main__":
    main()
