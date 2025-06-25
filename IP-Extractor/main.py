import socket
import requests
import ipaddress

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Couldn't fetch info"}
    except Exception as e:
        return {"error": str(e)}

def get_ips(domain):
    try:
        # Get all A records
        ips = socket.gethostbyname_ex(domain)[2]
        print(f"\nDomain: {domain}")
        for ip in ips:
            ip_type = "Private/Bogon" if is_private_ip(ip) else "Public"
            print(f"  -> IP: {ip} ({ip_type})")
            info = get_ip_info(ip)
            if "error" not in info:
                print(f"     - Org: {info.get('org')}")
                print(f"     - ASN: {info.get('asn', {}).get('asn', 'N/A')}")
                print(f"     - Location: {info.get('city', '')}, {info.get('region', '')}, {info.get('country', '')}")
            else:
                print(f"     - Info Error: {info['error']}")
    except Exception as e:
        print(f"Error for {domain}: {e}")

# Example usage
Hyy = input("Enter your domain:")
get_ips(Hyy)
