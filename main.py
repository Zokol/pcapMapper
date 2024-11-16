import json
import subprocess
import click
import os
import re

import numpy as np
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
import socket

DEBUG = False

import requests
import dns.resolver
import pandas as pd

from scapy.all import *
load_layer("tls")

import scapy.layers.tls.crypto.suites as suites

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


def human_readable_size(size_bytes):
    # Define the size units
    units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]

    # Initialize the unit index
    unit_index = 0

    # Convert the size to the appropriate unit
    while size_bytes >= 1024 and unit_index < len(units) - 1:
        size_bytes /= 1024.0
        unit_index += 1

    # IF smallest unit is not selected, format the size to two decimal places and append the unit
    if unit_index > 0:
        human_readable = f"{size_bytes:.2f} {units[unit_index]}"
    else:
        human_readable = f"{size_bytes:.0f} {units[unit_index]}"

    return human_readable

def filter_pcap(dut_ip=None, dut_mac=None, dir=None, input_file=None, output_file=None, DEBUG=False):
    if not input_file:
        raise Exception("No pcap file given")

    if not output_file:
        output_file = input_file.split(".")[0] + "_filtered.pcap"

    if not dir:
        if dut_ip:
            command = f"tshark -nnr {input_file} -f 'ip.addr == {dut_ip}' -w {output_file}"
        elif dut_mac:
            command = f"tshark -nnr {input_file} -Y 'eth.addr == {dut_mac}' -w {output_file}"
        else:
            raise Exception("No IP or MAC address given")
    elif dir == "src" or dir == "dst":
        if dut_ip:
            command = f"tshark -nnr {input_file} -Y 'ip.{dir} == {dut_ip}' -w {output_file}"
        elif dut_mac:
            command = f"tshark -nnr {input_file} -Y 'eth.{dir} == {dut_mac}' -w {output_file}"
        else:
            raise Exception("No IP or MAC address given")
    else:
        raise Exception("Invalid direction given:", dir, "expected 'src' or 'dst'")

    res = subprocess.run(command, shell=True, text=True, capture_output=True)
    if DEBUG: print(f"Command: {command}\nStdout: {res.stdout}\nStderr: {res.stderr}")

def normalize_mac(mac):
    # Remove any delimiters (colons, semicolons, dashes, or spaces) and convert to lowercase
    mac = re.sub(r'[:;.\s-]', '', mac.lower())

    # Insert colons at the appropriate positions
    normalized_mac = ':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))

    return normalized_mac

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
        try:
            response = reader.city(ip)
            result = {
                "ip": ip,
                "city": response.city.name,
                "country": response.country.iso_code,
                "lat": response.location.latitude,
                "lon": response.location.longitude
            }
        except AddressNotFoundError:
            result = {
                "ip": ip,
                "city": "Unknown",
                "country": "Unknown",
                "lat": "Unknown",
                "lon": "Unknown"
            }
        return result


def get_cipher_name_by_value(cipher_value):
    for name in dir(suites):
        obj = getattr(suites, name)
        if isinstance(obj, type) and hasattr(obj, 'val'):
            if obj.val == cipher_value:
                return name
    return None

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
            src = packet.strip().split(',')
            for ip in src:
                ip_addresses.add(ip)

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

def get_ip_stats(pcap_file, dir, dut_ip=None, dut_mac=None):
    # List IPs DUT recevies data from: `tshark -n -T fields -e ip.src -Y "ip.dst == $DUT_IP" -2 -r $PCAP_FILE | sort | uniq`
    if dir == 'src':
        res_dir = 'dst'
    else:
        res_dir = 'src'

    if dut_ip:
        command = f"tshark -n -T fields -e frame.len -e ip.proto -e ip.{res_dir} -R 'ip.{dir} == {dut_ip}' -2 -r {pcap_file}"
    elif dut_mac:
        command = f"tshark -n -T fields -e frame.len -e ip.proto -e ip.{res_dir} -R 'eth.{dir} == {dut_mac}' -2 -r {pcap_file}"
    else:
        raise Exception("No IP or MAC address given")
    stats = subprocess.run(command, shell=True, text=True, capture_output=True)
    if DEBUG: print(f"Command: {command}\nStdout: {stats.stdout}\nStderr: {stats.stderr}")
    lines = stats.stdout.split("\n")

    while '' in lines:
        lines.remove('')

    # Split each line into columns
    data = [line.split('\t') for line in lines if line]

    # Create a pandas DataFrame from the columns
    df = pd.DataFrame(data, columns=['frame_len', 'ip_protocol', 'ip_address'])

    # Replace empty strings with NaN
    df.replace('', np.nan, inplace=True)

    # Drop rows where any column has an empty value
    df = df.dropna()

    # Create a new DataFrame to store the results
    new_df = pd.DataFrame(columns=df.columns)

    # Iterate over the rows of the DataFrame
    for index, row in df.iterrows():
        if ',' in row['ip_protocol']:
            # Split the value into two integers
            values = row['ip_protocol'].split(',')
            for value in values:
                new_row = row.copy()
                new_row['ip_protocol'] = value
                new_df = pd.concat([new_df, pd.DataFrame([new_row])], ignore_index=True)
        else:
            new_df = pd.concat([new_df, pd.DataFrame([row])], ignore_index=True)

    new_df['ip_protocol'] = new_df['ip_protocol'].astype(int)
    new_df['frame_len'] = new_df['frame_len'].astype(int)

    new_df["ip_protocol"].apply(proto_name_by_num)

    result = {"protocols": {}, "protocols_by_ip": {}}
    for name, group in new_df.groupby('ip_address'):
        traffic = group.groupby('ip_protocol')['frame_len'].sum().to_dict()
        location = get_geoip(name)
        result["protocols_by_ip"][name] = {"location": location, "protocols": traffic}

    result["protocols"] = new_df.groupby('ip_protocol')['frame_len'].sum().to_dict()

    return result

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

def get_dns_requests(pcap_file, mac_address):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # List to store domain and IP information
    domain_ip_list = []

    # Iterate over each packet
    for packet in packets:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:  # DNS response
            if packet.haslayer(Ether) and packet[Ether].dst == mac_address:
                for i in range(packet[DNS].ancount):
                    dnsrr = packet[DNS].an[i]
                    if dnsrr.type == 1:  # A record
                        domain = dnsrr.rrname.decode('utf-8')
                        ip = dnsrr.rdata

                        domain_ip_list.append({'domain': domain, 'ip': ip})

    # Convert the list of dictionaries to a pandas DataFrame
    df = pd.DataFrame(domain_ip_list)

    return df

def get_protocol_stats_scapy(pcap_file, dir, dut_ip=None, dut_mac=None):
    if dir == 'src':
        res_dir = 'dst'
    else:
        res_dir = 'src'

    # Read the pcap file
    packets = rdpcap(pcap_file)

    # List to store packet information
    packet_info = []

    # Iterate over each packet
    for packet in packets:
        if packet.haslayer(IP):
            packet_data = {}
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            # Get the protocol stack
            protocols = ""
            layer = packet
            while layer:
                if protocols == "":
                    protocols += layer.name
                else:
                    protocols += " - " + layer.name
                layer = layer.payload
            packet_data['protocols'] = protocols

            # Find cipher name from Server Hello packets
            packet_data['tls_cipher'] = None
            if packet.haslayer(TLS):
                tls_layer = packet[TLS]
                if tls_layer.type == 22:
                    if tls_layer.msg[0].msgtype == 2:
                        cipher_value = tls_layer.fields["msg"][0].fields["cipher"]
                        cipher_name = get_cipher_name_by_value(cipher_value)
                        packet_data['tls_cipher'] = cipher_name
                        ## TODO: extract key length and trust chain from server hello packets


            if dir == 'src':
                if dut_ip and ip_src != dut_ip:
                    continue
                elif dut_mac and packet.src != dut_mac:
                    continue
                packet_data['ip_address'] = ip_dst
                if "TCP" in protocols:
                    packet_data['port'] = packet.sprintf("%TCP.dport%")
                elif "UDP" in protocols:
                    packet_data['port'] = packet.sprintf("%UDP.dport%")
            elif dir == 'dst':
                if dut_ip and ip_dst != dut_ip:
                    continue
                elif dut_mac and packet.dst != dut_mac:
                    continue
                packet_data['ip_address'] = ip_src
                if "TCP" in protocols:
                    packet_data['port'] = packet.sprintf("%TCP.sport%")
                elif "UDP" in protocols:
                    packet_data['port'] = packet.sprintf("%UDP.sport%")
            size = len(packet)
            packet_data['packet_size'] = size
            packet_info.append(packet_data)

    # Convert the list of dictionaries to a pandas DataFrame
    df = pd.DataFrame(packet_info)

    return df

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
@click.option("--dut_name", help="The name of the device under test", default=None)
@click.option("--ip", help="The IP address of the device under test", default=None)
@click.option("--pcap_file", help="The path to the pcap file", callback=validate_input, default=None)
@click.option("--pcap_folder", help="Path to folder containing pcaps", callback=validate_input, default=None)
@click.option("--output", help="Path to output file")
@click.option("--mac", help="Program resolves the IP address of the device under test from its MAC address", default=None)
@click.option("--debug", help="Enable debug mode", is_flag=True, default=False)
@click.option("--resolve_mac", help="Resolves MAC for given IP", is_flag=True, default=False)
@click.option("--resolve_ip", help="Resolves IP for given MAC", is_flag=True, default=False)
@click.option("--resolve_global", help="Resolves IP of each domain using DNS of each country", is_flag=True, default=False)
def run(dut_name, ip, pcap_file, pcap_folder, output, mac, debug, resolve_mac, resolve_ip, resolve_global):

    global DEBUG, ip_stats
    DEBUG = debug

    # Get ip as parameter using click
    DUT_IP = ip
    # Get pcap file as parameter using click
    PCAP_FILE = pcap_file
    # Get pcap folder as parameter using click
    PCAP_FOLDER = pcap_folder
    # Get output file as parameter using click
    OUTPUT_FILE = output

    # First normalize mac address, if it was given
    if mac:
        mac = normalize_mac(mac)

    if not dut_name:
        raise click.MissingParameter(param_hint="dut_name; Please provide the name of the device "
                                                "under test")

    if PCAP_FOLDER:
        files = []
        # List all pcap files in the folder
        pcap_files = [f for f in os.listdir(PCAP_FOLDER) if re.match(r'.*\.pcap\d+$', f)]
        # Iterate over all pcap files
        for pcap_file in pcap_files:
            files.append(os.path.join(PCAP_FOLDER, pcap_file))

    elif PCAP_FILE:
        # check that the file exists
        if not os.path.exists(PCAP_FILE):
            raise FileNotFoundError(f"{PCAP_FILE} not found")
        files = [PCAP_FILE]

    else:
        raise click.MissingParameter(param_hint="pcap_file or pcap_folder")

    domain_dfs = []
    ips = {"src": [], "dst": []}
    countries = {"src": [], "dst": []}
    protocols = {} # total bytes per protocol sent by DUT
    ip_stats_dfs = {"src": [], "dst": []}
    ip_stats = {"src": {}, "dst": {}}
    tls_stats = {"ciphers": {}}
    domains = []
    #global_dns_routing = []
    for pcap_file in files:
        print(f"Processing {pcap_file}")

        # Helper functions to quickly resolve IP or MAC address
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

        # Resolve IP or MAC, if only one of them was given as a parameter
        if mac:
            if not ip:
                dut_ips = find_ip_for_mac(pcap_file, mac)
                if not len(dut_ips):
                    print("Given MAC does not match to any packets in this file. Skipping...")
                    continue
        elif ip:
            dut_ips = [ip]
            if not mac:
                dut_macs = find_mac_for_ip(pcap_file, ip)
                if not len(dut_macs):
                    print("Given IP does not match to any packets in this file. Skipping...")
                    continue
                mac = dut_macs.pop()
        else:
            raise click.MissingParameter(param_hint="Please give IP or MAC address of the device under test")

        assert len(dut_ips), "No IP-address could be defined"
        assert mac, "No MAC-address could be defined"

        print("Device under test IP:", dut_ips)
        print("Device under test MAC:", mac)

        """
        # Get IPs from pcap file
        ips["dst"] += list_ips(pcap_file, 'src', dut_mac=mac)
        if len(ips["dst"]) == 0:
            print("No packets sent by DUT in this pcap file. Skipping...")
            continue
        ips["src"] += list_ips(pcap_file, 'dst', dut_mac=mac)
        print(ips)
        """

        """
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
        """

        # Get total bytes for each protocol from pcap file
        """
        protos = ["http", "ssl", "telnet", "ldap", "dns", "ftp", "smtp", "dhcp", "icmp", "ssh"]
        for proto in protos:
            print(f"Getting stats for {proto}")
            if proto not in protocols:
                protocols[proto] = 0
            protocols[proto] += get_filtered_stats(pcap_file, 'src', proto, dut_mac=mac)
        print(protocols)
        """

        # Get domains from pcap file
        domain_dfs.append(get_dns_requests(pcap_file, mac))

        # Get IP statistics
        ip_stats_dfs["src"].append(get_protocol_stats_scapy(pcap_file, 'src', dut_mac=mac))
        ip_stats_dfs["dst"].append(get_protocol_stats_scapy(pcap_file, 'dst', dut_mac=mac))

        """
        # Get global DNS routing
        if resolve_global:
            for domain in domains:
                global_dns_routing.append({"domain": domain, "routes": get_country_routes(domain)})
            print(global_dns_routing)
        """

    df_src = pd.concat(ip_stats_dfs["src"])
    if len(df_src) > 0:
        ip_stats["src"] = analyze_protocol_stats(df_src)
        countries["src"] = list(set([ip_stats["src"]["addresses"][ip]["location"]["country"] for ip in ip_stats["src"]["addresses"]]))

        # Get unique domains
        domain_df = pd.concat(domain_dfs)
        if len(domain_df) > 0:
            domains = list(domain_df['domain'].unique())

            # Match domains to each IP in ip_stats
            for ip in ip_stats["src"]["addresses"]:
                if ip in domain_df['ip'].unique():
                    ip_stats["src"]["addresses"][ip]["domains"] = list(domain_df[domain_df['ip'] == ip]['domain'])

        else:
            print("Warning: No DNS requests sent by DUT")

    else:
        print("Warning: No packets sent by DUT")

    df_dst = pd.concat(ip_stats_dfs["dst"])
    if len(df_dst) > 0:
        ip_stats["dst"] = analyze_protocol_stats(df_dst)
        countries["dst"] = list(set([ip_stats["dst"]["addresses"][ip]["location"]["country"] for ip in ip_stats["dst"]["addresses"]]))

        # List all TLS ciphers
        # Filter out all rows that don't have a TLS cipher, include all columns
        cipher_df = df_dst.dropna(subset=['tls_cipher'])
        tls_stats["ciphers"] = cipher_df.groupby('tls_cipher')['packet_size'].sum().to_dict()

    else:
        print("Warning: No packets received by DUT")

    output = {
        "dut": {
            "name": dut_name,
            "mac": mac,
            "ip": list(dut_ips)
        },
        "traffic_statistics": {
            "tls": tls_stats,
            "domains": domains,
            "countries": countries,
            "protocols": ip_stats
            #"global_routing": global_dns_routing
        }
    }

    import pprint
    pp = pprint.PrettyPrinter(depth=4)
    pp.pprint(output)

    # Write the results to the output file
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f)

def analyze_protocol_stats(df):

    ip_stats = {"ports": {}, "TLS_ciphers": {}, "addresses": {}}

    for name, group in df.groupby('ip_address'):
        port_traffic = {}
        for port, port_group in group.groupby('port'):

            # Calculate total packet size for this port
            bytes_per_port = port_group['packet_size'].sum()

            port_traffic[port] = {
                "total_bytes": human_readable_size(bytes_per_port),
                "protocol_stacks": []
            }

            # group the port group by protocols
            protocol_groups = port_group.groupby('protocols')

            # calculate the total packet size for each protocol
            for protocol, protocol_group in protocol_groups:
                bytes_per_protocol_stack = protocol_group['packet_size'].sum()
                ### Fetch all TLS ciphers associated with this IP
                tls_ciphers = df[df['ip_address'] == name]['tls_cipher'].unique()
                tls_ciphers = [item for item in tls_ciphers if item is not None]
                tls_ciphers_str = None
                if len(tls_ciphers) > 0:
                    tls_ciphers_str = str(tls_ciphers[0])
                if len(tls_ciphers) > 1:
                    tls_ciphers_str = ', '.join(set(tls_ciphers))
                port_traffic[port]["protocol_stacks"].append(
                    {
                        "protocol_stack": protocol,
                        "total_bytes": human_readable_size(bytes_per_protocol_stack),
                        #"tls": tls_ciphers_str
                    }
                )

        location = get_geoip(name)

        ip_stats["addresses"][name] = {
            "ports": port_traffic,
            "location": location
        }

    ip_stats["ports"] = df.groupby('port')['packet_size'].sum().to_dict()
    for port in ip_stats["ports"]:
        ip_stats["ports"][port] = human_readable_size(ip_stats["ports"][port])

    return ip_stats

if __name__ == "__main__":
    run()

