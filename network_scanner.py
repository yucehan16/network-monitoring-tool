"""
Wi-Fi Connected Devices Scanner

This script scans the entire local subnet to identify devices connected to the same Wi-Fi network.
"""

from scapy.all import ARP, Ether, srp

def scan_network(subnet):
    """Scan the network to find connected devices."""
    # Create an ARP request for the subnet
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the ARP request and receive responses
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    # Replace with your subnet (e.g., 192.168.1.0/24)
    network_subnet = "192.168.1.0/24"

    print(f"Scanning the network: {network_subnet}")
    devices = scan_network(network_subnet)

    if devices:
        print("\nConnected Devices:")
        print("IP Address\t\tMAC Address")
        print("-" * 40)
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
    else:
        print("No devices found on the network.")