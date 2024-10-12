import json
import subprocess
import click
import os
import re
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
import socket

DEBUG = False

import requests
import dns.resolver
import pandas as pd

NAMESERVER_CSV_URL = "https://public-dns.info/nameservers.csv"

DNS_SERVER_SHORTLIST = {
    "US": "128.238.2.38",
    "CN": "180.76.76.76",
    "DE": "46.182.19.48",
    "TR": "92.45.23.168",
    "JP": "210.190.105.66",
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1"
}

def read_nameserver_csv_from_url(url=NAMESERVER_CSV_URL):
    ## Convert CSV to pandas
    df = pd.read_csv(url)

    return df

def read_namesever_csv_from_file(file_path):
    ## Open CSV from parameter
    df = pd.read_csv(file_path)

    return df

def get_dns_for_each_country(pandas_dataframe):
    ## Sort rows by country_code-column and by reliability-column
    df = pandas_dataframe.sort_values(by=['country_code', 'reliability'], ascending=[True, False])
    df = df.drop_duplicates(subset='country_code', keep='first')

    return df

def resolve_ip(domain, dns_server_dataframe):
    results = {}

    for index, row in dns_server_dataframe.iterrows():
        ip = row['ip_address']
        name = str(row['country_code'])
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.lifetime = 0.5
        results[name] = []
        try:
            res = resolver.resolve(domain, 'A')
        except dns.resolver.NoAnswer:
            #print("No answer")
            continue
        except dns.resolver.LifetimeTimeout:
            #print("Timeout")
            continue
        except dns.resolver.NoNameservers:
            #print("No data")
            continue
        for rdata in res:
            results[name].append(rdata.address)
    return results

def get_geoip(ip):
    with Reader("GeoLite2-City.mmdb") as reader:
        response = reader.city(ip)
        result = {
            "ip": ip,
            "city": response.city.name,
            "country": response.country.iso_code,
            "lat": response.location.latitude,
            "lon": response.location.longitude
        }
        return result

def get_country_routes(domain):
    ## Read CSV from URL
    df = read_nameserver_csv_from_url()

    ## Get DNS for each country
    dns_servers = get_dns_for_each_country(df)

    ## Resolve IP
    dns_results = resolve_ip(domain, dns_servers)

    results = []
    for dns_country in dns_results:
        if len(dns_results[dns_country]):
            ip = dns_results[dns_country][0]
            data = get_geoip(ip)
            data["dns"] = dns_country
            results.append({"src": data["dns"], "dst": data["country"]})

    return results

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def validate_input(ctx, param, value):
    if not value and "pcap_file" not in ctx.params and "pcap_folder" not in ctx.params:
        raise click.MissingParameter(param_hint="pcap_file or pcap_folder")
    return value

def find_ip_for_mac(pcap_file, dut_mac):
    # Run the tshark command to get the IP addresses
    command = f'tshark -r {pcap_file} -Y "eth.src == {dut_mac}" -T fields -e ip.src'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if DEBUG: print(f"Command: {command}\nStdout: {result.stdout}\nStderr: {result.stderr}")

    # Split the output by newline to get each packet
    packets = result.stdout.split('\n')

    # Extract the IP addresses and remove duplicates
    ip_addresses = set()
    for packet in packets:
        if packet:
            src = packet.strip()
            ip_addresses.add(src)

    return ip_addresses

def find_mac_for_ip(pcap_file, dut_ip):
    # Run the tshark command to get the MAC addresses
    command = f'tshark -r {pcap_file} -Y "ip.src == {dut_ip}" -T fields -e eth.src'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if DEBUG: print(f"Command: {command}\nStdout: {result.stdout}\nStderr: {result.stderr}")

    # Split the output by newline to get each packet
    packets = result.stdout.split('\n')

    # Extract the MAC addresses and remove duplicates
    mac_addresses = set()
    for packet in packets:
        if packet:
            src = packet.strip()
            mac_addresses.add(src)

    return mac_addresses

def list_domains(pcap_file, dut_ip=None, dut_mac=None):
    if dut_ip:
        command = f"tshark -n -T fields -e dns.qry.name -R 'ip.src == {dut_ip} && dns.flags.response eq 0' -2 -r {pcap_file} | sort | uniq"
    elif dut_mac:
        command = f"tshark -n -T fields -e dns.qry.name -R 'eth.src == {dut_mac} && dns.flags.response eq 0' -2 -r {pcap_file} | sort | uniq"
    else:
        raise Exception("No IP or MAC address given")

    ## List all domains in pcap using tshark
    domains = subprocess.run(command, shell=True, text=True, capture_output=True)
    if DEBUG: print(f"Command: {command}\nStdout: {domains.stdout}\nStderr: {domains.stderr}")
    domains = domains.stdout.split("\n")

    while '' in domains:
        domains.remove('')

    return domains

def list_ips(pcap_file, dir, dut_ip=None, dut_mac=None):
    # List IPs DUT recevies data from: `tshark -n -T fields -e ip.src -Y "ip.dst == $DUT_IP" -2 -r $PCAP_FILE | sort | uniq`
    if dir == 'src':
        res_dir = 'dst'
    else:
        res_dir = 'src'

    if dut_ip:
        command = f"tshark -n -T fields -e ip.{res_dir} -R 'ip.{dir} == {dut_ip}' -2 -r {pcap_file} | sort | uniq"
    elif dut_mac:
        command = f"tshark -n -T fields -e ip.{res_dir} -R 'eth.{dir} == {dut_mac}' -2 -r {pcap_file} | sort | uniq"
    else:
        raise Exception("No IP or MAC address given")
    ips = subprocess.run(command, shell=True, text=True, capture_output=True)
    if DEBUG: print(f"Command: {command}\nStdout: {ips.stdout}\nStderr: {ips.stderr}")
    ips = ips.stdout.split("\n")

    while '' in ips:
        ips.remove('')

    # Create a new list to store the IPs
    new_ips = []

    # Iterate over the original list
    for ip in ips:
        # Split each item and add the resulting items to the new list
        new_ips.extend(ip.split(','))

    return list(set(new_ips))

def get_protocol_stats(pcap_file, ip, dir):
    command = f"tshark -r {pcap_file} -Y 'ip.{dir} == {ip}' -T fields -e ip.proto -e frame.len"
    protocol_bytes = subprocess.run(command, shell=True, text=True, capture_output=True)
    if DEBUG: print(f"Command: {command}\nStdout: {protocol_bytes.stdout}\nStderr: {protocol_bytes.stderr}")
    protocol_bytes = protocol_bytes.stdout.split("\n")

    protocols = {}

    while '' in protocol_bytes:
        protocol_bytes.remove('')

    for line in protocol_bytes:
        protocol, length = line.split("\t")
        if protocol in protocols:
            protocols[protocol]["bytes"] += int(length)
        else:
            if ',' in protocol: ## Special case, multiple protocols in one packet
                tmp = protocol.split(',')
                name = []
                for proto in tmp:
                    name.append(proto_name_by_num(int(proto)))
                protocols[protocol] = {"ip": ip, "bytes": int(length), "protocol_name": ', '.join(name)}
            else:
                protocols[protocol] = {"ip": ip, "bytes": int(length), "protocol_name": proto_name_by_num(int(protocol))}

    return protocols

def get_filtered_stats(pcap_file, dir, filter, dut_ip=None, dut_mac=None):
    if dut_ip:
        command = f"tshark -r {pcap_file} -Y '{filter} && ip.{dir} == {dut_ip}' -T fields -e frame.len | awk \'{{s+=$1}} END {{print s}}\'"
    elif dut_mac:
        command = f"tshark -r {pcap_file} -Y '{filter} && eth.{dir} == {dut_mac}' -T fields -e frame.len | awk \'{{s+=$1}} END {{print s}}\'"
    else:
        raise Exception("No IP or MAC address given")
    bytes = subprocess.run(command, shell=True, text=True, capture_output=True)
    if DEBUG: print(f"Command: {command}\nStdout: {bytes.stdout}\nStderr: {bytes.stderr}")
    bytes = bytes.stdout.strip()
    if not bytes:
        return 0
    else:
        return int(bytes)

@click.command()
@click.option("--ip", help="The IP address of the device under test", default=None)
@click.option("--pcap_file", help="The path to the pcap file", callback=validate_input, default=None)
@click.option("--pcap_folder", help="Path to folder containing pcaps", callback=validate_input, default=None)
@click.option("--output", help="Path to output file")
@click.option("--mac", help="Program resolves the IP address of the device under test from its MAC address", default=None)
@click.option("--debug", help="Enable debug mode", is_flag=True, default=False)
@click.option("--resolve_mac", help="Resolves MAC for given IP", is_flag=True, default=False)
@click.option("--resolve_ip", help="Resolves IP for given MAC", is_flag=True, default=False)
@click.option("--resolve_global", help="Resolves IP of each domain using DNS of each country", is_flag=True, default=False)
def run(ip, pcap_file, pcap_folder, output, mac, debug, resolve_mac, resolve_ip, resolve_global):

    global DEBUG
    DEBUG = debug

    # Get ip as parameter using click
    DUT_IP = ip
    # Get pcap file as parameter using click
    PCAP_FILE = pcap_file
    # Get pcap folder as parameter using click
    PCAP_FOLDER = pcap_folder
    # Get output file as parameter using click
    OUTPUT_FILE = output

    if PCAP_FOLDER:
        files = []
        # List all pcap files in the folder
        pcap_files = [f for f in os.listdir(PCAP_FOLDER) if re.match(r'.*\.pcap\d+$', f)]
        # Iterate over all pcap files
        for pcap_file in pcap_files:
            files.append(os.path.join(PCAP_FOLDER, pcap_file))
            # List all domains in the pcap file

    else:
        files = [PCAP_FILE]

    domains = []
    ips = {"src": [], "dst": []}
    countries = {"src": [], "dst": []}
    protocols = {} # total bytes per protocol sent by DUT
    global_dns_routing = []
    for pcap_file in files:
        print(f"Processing {pcap_file}")

        if resolve_mac:
            if not ip:
                raise click.MissingParameter(param_hint="Please give IP address to resolve MAC address")
            macs = find_mac_for_ip(pcap_file, ip)
            print(f"MAC addresses for IP {ip} are {macs}")
            return

        if resolve_ip:
            if not mac:
                raise click.MissingParameter(param_hint="Please give MAC address to resolve IP address")
            ips = find_ip_for_mac(pcap_file, mac)
            print(f"IP addresses for MAC {mac} are {ips}")
            return

        if not ip:
            if mac:
                dut_ips = find_ip_for_mac(pcap_file, mac)
            else:
                raise click.MissingParameter(param_hint="Please give IP or MAC address of the device under test")
        else:
            dut_ips = [ip]
            mac = find_mac_for_ip(pcap_file, ip)
            print("MAC address for DUT IP", ip, "is", mac)

        print(f"Device under test IPs: {dut_ips}")
        if not len(dut_ips):
            print("No IP addresses found for DUT in this file. Skipping...")
            continue

        # Get IPs from pcap file
        ips["dst"] += list_ips(pcap_file, 'src', dut_mac=mac)
        if len(ips["dst"]) == 0:
            print("No packets sent by DUT in this pcap file. Skipping...")
            continue
        ips["src"] += list_ips(pcap_file, 'dst', dut_mac=mac)
        print(ips)

        # Get domains from pcap file
        domains += list_domains(pcap_file, dut_mac=mac)
        print(domains)

        # Get countries where DUT communicates to/from
        for ip in ips["src"]:
            try: countries["src"].append(get_geoip(ip))
            except AddressNotFoundError:
                continue
        for ip in ips["dst"]:
            try: countries["dst"].append(get_geoip(ip))
            except AddressNotFoundError:
                continue
        print(countries)

        # Get total bytes for each protocol from pcap file
        protos = ["http", "ssl", "telnet", "ldap", "dns", "ftp", "smtp", "dhcp", "icmp", "ssh"]
        #protos = ["http", "ssl"]
        for proto in protos:
            print(f"Getting stats for {proto}")
            if proto not in protocols:
                protocols[proto] = 0
            protocols[proto] += get_filtered_stats(pcap_file, 'src', proto, dut_mac=mac)
        print(protocols)

        if resolve_global:
            for domain in domains:
                global_dns_routing.append({"domain": domain, "routes": get_country_routes(domain)})
            print(global_dns_routing)

    output = {
        "domains": domains,
        "ips": ips,
        "countries": countries,
        "protocols": protocols,
        "global_routing": global_dns_routing
    }

    # Write the results to the output file
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f)

if __name__ == "__main__":
    run()

