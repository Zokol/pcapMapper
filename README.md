# pcapMapper

This Python application is designed to give you a quick insight on the network traffic captured in pcap files.

**Disclaimer: This project is currently under active development. Stability and functionality are not guaranteed at this stage. Use at your own risk.**


## Features

- Resolve MAC address for a given IP address
  - Device might not tell its MAC-address in the UI, it might not be etched on the device enclosure, but it is useful and relatively static unique identifier for the device.
  - If you know one IP-address that the device uses, you can use this feature to list all MAC-addresses that are the known IP-address for communication.
  - Depending on the device, it is possible that it tries to prevent tracking by changing its MAC-address. In this case, this feature does not provide reliable information.
- Resolve IP address for a given MAC address
  - Device may use multiple IP-addresses during its operation, but the MAC-address is usually static.
  - If you know the MAC-address of the device, you can use this feature to list all IP-addresses that are known to be used by the device.
- List all domains communicated with in a pcap file
  - Domains are human-readable names for IP-addresses.
  - They usually give you good insight on the services that the device backend is built on.
  - This feature lists all domains that the device has communicated with.
- List all IPs communicated with in a pcap file
  - IP-addresses are the actual addresses of the backend-servers that the device communicates with. 
  - These addresses often give you insight on the location of where the data is sent to or received from.
  - This feature lists all IP-addresses that the device has communicated with.
- Get geographical information about the IPs communicated with
  - IP-addresses have relation to geographical locations.
  - Location of a backend server can be useful when inspecting which territories and legistlation might apply to the data.
  - This feature uses the GeoIP2 database to get the geographical information about the IP-addresses.
- Get total bytes for each protocol from pcap file
  - Device might communicate with various protocols. Some protocols might be interesting, some might be red flags when evaluating device security.
  - This feature gives you a statistical view on the amount of data transferred with each protocol.
- Resolve IP of each domain using DNS of each country
  - Domains are resolved into IP-addresses using DNS-servers. Usually the DNS-server is defined by your ISP, and in this case it is the DNS-server of the country you are in.
  - Imagine you take a device with you to another country. As the DNS-server changes, the device might communicate with different servers in this new location.
  - This feature resolves the requested domains into IP-address using the DNS-servers of each country, and resolves the geolocation of the IP-addresses. Resulting map describes source and destination locations based on these geolocations of the IP-addresses.

## Installation

```
python -m pip install -r requirements.txt
```

## Filtering pcaps

If you are dealing with large packet captures, you can use the included bash script to extract only the packets sent or received by the inspected device.
The script also combines all of these packets into single pcap-file.

Usage: 
```bash
extract_dut_packets.sh [ip|mac] [IP or MAC ADDRESS] [OUTPUT PCAP FILE] [INPUT PCAP FOLDER]
```

To extract and combine packets from `pcaps`-folder sent and received by 192.168.0.10:
```bash
extract_dut_packets.sh ip 192.168.0.10 dut_packets.pcap ./pcaps
```


## Usage

Basic syntax is:
```bash
python main.py --ip <ip_address> --pcap_file <path_to_pcap_file> --output <path_to_output_file>
```

### If you want to analyze all pcaps in folder:
```bash
python main.py --ip 192.168.1.2 --pcap_folder /path/to/folder --output output.json
```

### If you know DUT IP
```bash
python main.py --ip 192.168.0.10 --pcap_file input.pcap --output output.json
```

### If you know DUT MAC
```bash
python main.py --mac 00:00:00:00:00:00 --pcap_file input.pcap --output output.json
```

### If you want to resolve MAC address
```bash
python main.py --resolve_mac --ip 192.168.1.42 --pcap_file input.pcap --output output.json
```

### If you want to resolve IP address
```bash
python main.py --resolve_ip --mac 00:00:00:00:00:00 --pcap_file input.pcap --output output.json
```

You can also use the following options:

- `--mac`: Program resolves the IP address of the device under test from its MAC address
- `--ip`: Program resolves the MAC address of the device under test from its IP address
- `--pcap_file`: Path to the pcap file
- `--pcap_folder`: Path to the folder containing pcap files
- `--output`: Path to the output file
- `--debug`: Enable debug mode
- `--resolve_mac`: Resolves MAC for given IP
- `--resolve_ip`: Resolves IP for given MAC
- `--resolve_global`: Resolves IP of each domain using DNS of each country

## Output

The output of the application is a JSON file containing the following information:

- List of domains communicated with
- List of IPs communicated with
- Geographical information about the IPs communicated with
- Total bytes for each protocol
- Global DNS routing information for each domain