import scapy.all as scapy
import argparse
import time
import random
import subprocess

def get_arguments():
    parser = argparse.ArgumentParser(description="Advanced ARP Network Scanner with Stealth and MAC Spoofing")
    parser.add_argument("-r", "--range", dest="network_ip", required=True, help="Target IP range (e.g., 192.168.1.1/24)")
    parser.add_argument("-s", "--stealth", action="store_true", help="Enable stealth mode (adds delay between packets)")
    parser.add_argument("-d", "--delay", type=str, help="Delay between packets (e.g., 1.5 or 'random')")
    parser.add_argument("-i", "--interface", type=str, help="Network interface (e.g., eth0 or wlan0)")
    parser.add_argument("-m", "--mac-spoof", action="store_true", help="Spoof MAC address before scan")
    return parser.parse_args()

def generate_random_mac():
    mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0xFF) for _ in range(5))
    return mac

def change_mac(interface, new_mac):
    print(f"[+] Changing MAC address of {interface} to {new_mac}")
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["sudo", "ifconfig", interface, "up"])

def scan(network_ip, stealth=False, delay=None):
    arp_request = scapy.ARP(pdst=network_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request_broadcast = broadcast / arp_request
    answered, _ = scapy.srp(request_broadcast, timeout=1, verbose=False)

    clients = []
    for i, answer in enumerate(answered):
        client = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        clients.append(client)

        if stealth:
            if delay == "random":
                sleep_time = round(random.uniform(0.5, 2.0), 2)
            else:
                try:
                    sleep_time = float(delay)
                except:
                    sleep_time = 1.0
            print(f"[+] Waiting {sleep_time}s before next request (stealth mode)...")
            time.sleep(sleep_time)
    return clients

def display_clients(clients):
    print("\n{:<20} {:<20}".format("IP Address", "MAC Address"))
    print("=" * 40)
    for client in clients:
        print("{:<20} {:<20}".format(client["ip"], client["mac"]))

if __name__ == "__main__":
    try:
        args = get_arguments()

        if args.mac_spoof:
            if not args.interface:
                print("[-] You must specify --interface or -i when using --mac-spoof")
                exit()
            new_mac = generate_random_mac()
            change_mac(args.interface, new_mac)

        print("[*] Starting scan...")
        clients = scan(args.network_ip, stealth=args.stealth, delay=args.delay)
        display_clients(clients)
        print(f"\n[✓] Scan complete. {len(clients)} device(s) found.")

    except Exception as e:
        print(f"[!] Error: {e}")
