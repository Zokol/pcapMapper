# Network Analysis Tool

This Python application is designed to analyze network traffic captured in pcap files. It provides various functionalities such as resolving IP addresses from MAC addresses, listing domains and IPs communicated with, and getting geographical information about the IPs. It also provides protocol statistics and global DNS routing information.

## Features

- Resolve MAC address for a given IP address
- Resolve IP address for a given MAC address
- List all domains communicated with in a pcap file
- List all IPs communicated with in a pcap file
- Get geographical information about the IPs communicated with
- Get total bytes for each protocol from pcap file
- Resolve IP of each domain using DNS of each country

## Dependencies

This application requires the following Python libraries:

- json
- subprocess
- click
- os
- re
- geoip2
- socket
- requests
- dns.resolver
- pandas

## Usage

To run the application, use the following command:

```bash
python main.py --ip <ip_address> --pcap_file <path_to_pcap_file> --output <path_to_output_file>
```

You can also use the following options:

- `--mac`: Program resolves the IP address of the device under test from its MAC address
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

## Note

This application is designed to work with pcap files. Make sure you have the necessary permissions to read the pcap files.