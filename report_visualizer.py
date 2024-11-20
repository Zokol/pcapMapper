import json
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import seaborn as sns
from glob import glob
import tldextract

# Function to convert human-readable sizes to bytes
def size_to_bytes(size_str):
    size_units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    size, unit = size_str.split()
    return int(float(size) * size_units[unit])

def bytes_to_human_readable(size_bytes):
    size_units = ["B", "KB", "MB", "GB", "TB"]
    size = size_bytes
    unit = size_units.pop(0)
    while size >= 1024 and size_units:
        size /= 1024
        unit = size_units.pop(0)
    return f"{size:.2f} {unit}"

# Function to parse the JSON report
def parse_report(report):
    data = json.loads(report)
    traffic_stats = data['traffic_statistics']

    # Extract ports data
    ports_data = []
    for direction in ['src', 'dst']:
        for port, size in traffic_stats['protocols'][direction].get('ports', {}).items():
            ports_data.append({'port': port, 'size_bytes': size_to_bytes(size), 'direction': direction})

    # Extract TLS data
    tls_data = []
    if 'tls' in traffic_stats:
        if 'ciphers' in traffic_stats['tls']:
            for cipher in traffic_stats['tls']['ciphers']:
                if isinstance(traffic_stats['tls']['ciphers'][cipher], str):
                    tls_data.append({'cipher': cipher, 'size_bytes': size_to_bytes(traffic_stats['tls']['ciphers'][cipher])})
                else:
                    tls_data.append({'cipher': cipher, 'size_bytes': traffic_stats['tls']['ciphers'][cipher]})
        if 'versions' in traffic_stats['tls']:
            for version in traffic_stats['tls']['versions']:
                if isinstance(traffic_stats['tls']['versions'][version], str):
                    tls_data.append({'version': version, 'size_bytes': size_to_bytes(traffic_stats['tls']['versions'][version])})
                else:
                    tls_data.append({'version': version, 'size_bytes': traffic_stats['tls']['versions'][version]})

    # Extract protocols data and domains
    protocols_data = []
    domains_data = []
    countries_data = []
    for direction in ['src', 'dst']:
        for address, details in traffic_stats['protocols'][direction].get('addresses', {}).items():
            if 'domains' in details:
                size = 0
                for port, port_details in details['ports'].items():
                    size += size_to_bytes(port_details['total_bytes'])
                for domain in list(set(details['domains'])):
                    domains_data.append({'domain': domain, 'size_bytes': size, 'direction': direction})
            if 'location' in details:
                data_sum = sum([size_to_bytes(port_details['total_bytes']) for port_details in details['ports'].values()])
                countries_data.append({'country': details['location']['country'], 'direction': direction, "size_bytes": data_sum})
            for port, port_details in details['ports'].items():
                for protocol_stack in port_details['protocol_stacks']:
                    layers = protocol_stack['protocol_stack'].split(' - ')
                    protocol_entry = {
                        'size_bytes': size_to_bytes(protocol_stack['total_bytes']),
                        'direction': direction
                    }
                    for i, layer in enumerate(layers):
                        protocol_entry[f'layer_{i+1}'] = layer
                    protocols_data.append(protocol_entry)

    # If same domains receive data, add them to one row
    if domains_data:
        domains_data = pd.DataFrame(domains_data).groupby(['domain', 'direction']).sum().reset_index().to_dict('records')

    if countries_data:
        countries_data = pd.DataFrame(countries_data).groupby(['country', 'direction']).sum().reset_index().to_dict('records')

    return countries_data, ports_data, protocols_data, domains_data, tls_data

# Function to visualize countries by amount of data
def visualize_countries(countries_data):
    df = pd.DataFrame(countries_data)
    # Filter out Unknown country
    df = df[df['country'] != 'Unknown']

    # Adjust the values and the label of the axis based on the data size
    max_size = df['size_bytes'].max()
    if max_size >= 1024 ** 4:
        df['size_bytes'] /= 1024 ** 4
        size_label = 'Size (TB)'
    elif max_size >= 1024 ** 3:
        df['size_bytes'] /= 1024 ** 3
        size_label = 'Size (GB)'
    elif max_size >= 1024 ** 2:
        df['size_bytes'] /= 1024 ** 2
        size_label = 'Size (MB)'
    elif max_size >= 1024:
        df['size_bytes'] /= 1024
        size_label = 'Size (KB)'
    else:
        size_label = 'Size (Bytes)'

    plt.figure(figsize=(10, 5))
    plt.xscale('log')
    plt.xlabel(size_label)
    sns.barplot(data=df, x='size_bytes', y='country', hue='direction', orient='h')
    plt.ylabel('Country')
    plt.title('Countries by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()
    plt.show()

# Function to visualize ports by amount of data
def visualize_ports(ports_data):
    df = pd.DataFrame(ports_data)
    sns.barplot(data=df, x='port', y='size_bytes', hue='direction')
    plt.title('Ports by Amount of Data')
    plt.show()

# Function to visualize protocols by amount of data
def visualize_protocols(protocols_data):
    df = pd.DataFrame(protocols_data)

    # Identify the highest layer number for each protocol entry
    df['highest_layer'] = df.filter(like='layer_').apply(lambda x: x.dropna().iloc[-1], axis=1)

    # Extract the corresponding layer and total_bytes for each entry
    df_highest_layer = df[['highest_layer', 'size_bytes', 'direction']].copy()

    # Adjust the values and the label of the axis based on the data size
    max_size = df_highest_layer['size_bytes'].max()
    if max_size >= 1024 ** 4:
        df_highest_layer['size_bytes'] /= 1024 ** 4
        size_label = 'Size (TB)'
    elif max_size >= 1024 ** 3:
        df_highest_layer['size_bytes'] /= 1024 ** 3
        size_label = 'Size (GB)'
    elif max_size >= 1024 ** 2:
        df_highest_layer['size_bytes'] /= 1024 ** 2
        size_label = 'Size (MB)'
    elif max_size >= 1024:
        df_highest_layer['size_bytes'] /= 1024
        size_label = 'Size (KB)'
    else:
        size_label = 'Size (Bytes)'

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 5))
    sns.barplot(data=df_highest_layer, x='size_bytes', y='highest_layer', hue='direction', orient='h')
    plt.xscale('log')
    plt.xlabel(size_label)
    plt.ylabel('Highest Layer')
    plt.title('Protocols by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()
    plt.show()

# Function to visualize protocol layers using plotly Parallel Categories Diagram
def visualize_protocol_layers(protocols_data):
    df = pd.DataFrame(protocols_data)
    max_layers = max(df.filter(like='layer_').apply(lambda x: x.notna().sum(), axis=1))
    for i in range(1, max_layers + 1):
        df[f'layer_{i}'] = df.get(f'layer_{i}', None)
    for index, row in df.iterrows():
        last_valid = None
        for i in range(1, max_layers + 1):
            if pd.isna(row[f'layer_{i}']):
                df.at[index, f'layer_{i}'] = last_valid
            else:
                last_valid = row[f'layer_{i}']
    layer_columns = [f'layer_{i}' for i in range(1, max_layers + 1)]

    # Order categories so that smallest groups are on the bottom
    for col in layer_columns:
        df[col] = pd.Categorical(df[col], categories=df.groupby(col)['size_bytes'].sum().sort_values(ascending=False).index)

    fig = px.parallel_categories(df, dimensions=layer_columns, color='size_bytes',
                                 color_continuous_scale=px.colors.sequential.Inferno)
    fig.update_layout(title='Distribution of Ethernet protocols by amount of data')
    fig.show()


def extract_tld(domain):
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"

def visualize_domains(domains_data):
    df = pd.DataFrame(domains_data)

    # Extract TLD from each domain
    df['tld'] = df['domain'].apply(extract_tld)

    # Group by TLD and direction
    tld_counts = df.groupby(['tld', 'direction']).sum().reset_index()

    # Group manufacturer-owned (not amazon, cloudflare, iotcplatform or ntp) domains into single group
    non_manufacturer_domains = [
        'amazonaws.com',
        'cloudflare.net',
        'ntp.org',
        'iotcplatform.com'
    ]

    # Adjust the values and the label of the axis based on the data size
    max_size = tld_counts['size_bytes'].max()
    if max_size >= 1024 ** 4:
        tld_counts['size_bytes'] /= 1024 ** 4
        size_label = 'Size (TB)'
    elif max_size >= 1024 ** 3:
        tld_counts['size_bytes'] /= 1024 ** 3
        size_label = 'Size (GB)'
    elif max_size >= 1024 ** 2:
        tld_counts['size_bytes'] /= 1024 ** 2
        size_label = 'Size (MB)'
    elif max_size >= 1024:
        tld_counts['size_bytes'] /= 1024
        size_label = 'Size (KB)'
    else:
        size_label = 'Size (Bytes)'

    # Plot the data with count of domains for each TLD on the horizontal axis
    plt.figure(figsize=(12, 6))
    sns.barplot(data=tld_counts, x='size_bytes', y='tld', hue='direction', orient='h')
    plt.xlabel(size_label)
    plt.xscale('log')
    plt.ylabel('Top-Level Domain (TLD)')
    plt.title('Domains Grouped by TLD')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()
    plt.show()

def visualize_tls_ciphers(tls_data):
    df = pd.DataFrame(tls_data)

    # Adjust the values and the label of the axis based on the data size
    max_size = df['size_bytes'].max()
    if max_size >= 1024 ** 4:
        df['size_bytes'] /= 1024 ** 4
        size_label = 'Size (TB)'
    elif max_size >= 1024 ** 3:
        df['size_bytes'] /= 1024 ** 3
        size_label = 'Size (GB)'
    elif max_size >= 1024 ** 2:
        df['size_bytes'] /= 1024 ** 2
        size_label = 'Size (MB)'
    elif max_size >= 1024:
        df['size_bytes'] /= 1024
        size_label = 'Size (KB)'
    else:
        size_label = 'Size (Bytes)'

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 5))
    sns.barplot(data=df, x='size_bytes', y='cipher', orient='h')
    plt.xscale('log')
    plt.xlabel(size_label)
    plt.ylabel('Cipher')
    plt.title('TLS Ciphers by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()
    plt.show()

def visualize_tls_versions(tls_data):
    df = pd.DataFrame(tls_data)

    # Adjust the values and the label of the axis based on the data size
    max_size = df['size_bytes'].max()
    if max_size >= 1024 ** 4:
        df['size_bytes'] /= 1024 ** 4
        size_label = 'Size (TB)'
    elif max_size >= 1024 ** 3:
        df['size_bytes'] /= 1024 ** 3
        size_label = 'Size (GB)'
    elif max_size >= 1024 ** 2:
        df['size_bytes'] /= 1024 ** 2
        size_label = 'Size (MB)'
    elif max_size >= 1024:
        df['size_bytes'] /= 1024
        size_label = 'Size (KB)'
    else:
        size_label = 'Size (Bytes)'

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 5))
    sns.barplot(data=df, x='size_bytes', y='version', orient='h')
    plt.xscale('log')
    plt.xlabel(size_label)
    plt.ylabel('TLS Version')
    plt.title('TLS Versions by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()
    plt.show()

if __name__ == '__main__':

    # Load and parse multiple reports
    report_files = glob('reports/*.json')
    all_countries_data = []
    all_ports_data = []
    all_protocols_data = []
    all_domains_data = []
    all_tls_data = []

    for report_file in report_files:
        with open(report_file, 'r') as file:
            report = file.read()
            countries_data, ports_data, protocols_data, domains_data, tls_data = parse_report(report)
            all_countries_data.extend(countries_data)
            all_ports_data.extend(ports_data)
            all_protocols_data.extend(protocols_data)
            all_domains_data.extend(domains_data)
            all_tls_data.extend(tls_data)

    # Visualize aggregated data
    visualize_countries(all_countries_data)
    visualize_protocols(all_protocols_data)
    #visualize_protocol_layers(all_protocols_data)
    visualize_domains(all_domains_data)
    visualize_tls_versions(all_tls_data)
    visualize_tls_ciphers(all_tls_data)