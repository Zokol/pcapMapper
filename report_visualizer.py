import json
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import seaborn as sns
from glob import glob
import tldextract
import os
import click
import requests
import dns.resolver

# Group common domains into categories
DOMAIN_GROUPS = {
    "[CDN]": [
        'akamai.net',
        'cloudfront.net',
        'akamaiedge.net',
        'gstatic.com',
        'fastly.net',
        'phicdn.net',
        'aaplimg.com',
        'akamai.net',
        'akamaiedge.net',
        'cloudflare.com',
        'cloudflare.net',
        'bootstrapcdn.com',
        '127.net',
        'hinetcdn.com.tw',
    ],
    "[GOOGLE]": [
        'app-analytics-services.com',
        'app-measurement.com',
        'firebase.io.com',
        'firebaseio.com',
        'google.com',
        'googleapis.com',
        'googleusercontent.com',
    ],
    "[DNS]": [
        'akadns.net',
        'apple-dns.net',
        'one.one',
        'iot-dns.com',
        'alibabadns.com',
    ],
    "[AWS]": [
        'aws.com',
        'awsglobalaccelerator.com',
        'amazonaws.com',
    ],
    "[MICROSOFT]": [
        'microsoft.com',
        'github.com'
        'azure.com',
    ],
    "[ALIBABA]": [
        'alibabadns.com',
        'aliyuncs.com',
        'aliyunga009.com',
        'aliyunga0019.com',
    ]
}

# Group common nameservers into categories
NAMESERVER_GROUPS = {
    "[AWS]":
    [
        'awsdns'
    ],
    "[GOOGLE]":
    [
        'google',
    ],
}

# Whitelist of domains operated by large and global companies (e.g. amazon, cloudflare or iotcplatform)
NON_MANUFACTURER_DOMAINS = [
    'amazonaws.com',
    'ntp.org',
    'iotcplatform.com',
    'klarna.net',
    'microsoft.com',
    'lokalise.com.',
    'apple.com',
    'adobe.com',
    'facebook.com',
    'twitter.com',
    'paypal.com',
    'stripe.com',
    'github.com',
    'linkedin.com',
    'dropbox.com',
    'slack.com',
    'zoom.us',
    'zendesk.com',
    'split.io.',
    'leanplum.com',
    'branch.io',
    'googleapis.com',
    'lokalise.com',
    'privacy-center.org',
    'gstatic.com',
    'lokalise.co',
    'shipup.co',
    'emb-api.com',
    'app-analytics-services.com',
    'app-measurement.com',
    'firebase.io.com',
    'firebaseio.com',
    'akadns.net',
    'apple-dns.net',
    'akamai.net',
    'cloudfront.net',
    'akamaiedge.net',
    'fastly.net',
    'phicdn.net',
    'aaplimg.com',
    'akamai.net',
    'akamaiedge.net',
    'cloudflare.com',
    'one.one',
    '127.net',
    'ytimg.org',
    'alibabadns.com',
    'aliyuncs.com',
    'aliyunga009.com',
    'aws.com',
    'awsglobalaccelerator.com',
    'azure.com',
    'bootstrapcdn.com',
    'dvv.fi',
    'fastly-edge.com',
    'googleusercontent.com',
    'helpshift.com',
    'hinetcdn.com.tw',
    'iot-dns.com',
    'mozgcp.net',
    'ndmdhs.com',
    'netease.com',
    'sina.com.cn',
    'tuyaeu.com',
    'ytimg.com'
]

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
def parse_report(report, device_id=None):
    data = json.loads(report)
    traffic_stats = data['traffic_statistics']

    # Extract ports data
    ports_data = []
    for direction in ['src', 'dst']:
        for port, size in traffic_stats['protocols'][direction].get('ports', {}).items():
            ports_data.append({'port': port, 'size_bytes': size_to_bytes(size), 'direction': direction, 'device_id': device_id})

    # Extract TLS data
    tls_data = []
    if 'tls' in traffic_stats:
        if 'ciphers' in traffic_stats['tls']:
            for cipher in traffic_stats['tls']['ciphers']:
                if isinstance(traffic_stats['tls']['ciphers'][cipher], str):
                    tls_data.append({'cipher': cipher, 'size_bytes': size_to_bytes(traffic_stats['tls']['ciphers'][cipher]), 'device_id': device_id})
                else:
                    tls_data.append({'cipher': cipher, 'size_bytes': traffic_stats['tls']['ciphers'][cipher], 'device_id': device_id})
        if 'versions' in traffic_stats['tls']:
            for version in traffic_stats['tls']['versions']:
                if isinstance(traffic_stats['tls']['versions'][version], str):
                    tls_data.append({'version': version, 'size_bytes': size_to_bytes(traffic_stats['tls']['versions'][version]), 'device_id': device_id})
                else:
                    tls_data.append({'version': version, 'size_bytes': traffic_stats['tls']['versions'][version], 'device_id': device_id})

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
                    domains_data.append({'domain': domain, 'size_bytes': size, 'direction': direction, 'device_id': device_id})
            if 'location' in details:
                data_sum = sum([size_to_bytes(port_details['total_bytes']) for port_details in details['ports'].values()])
                countries_data.append({'country': details['location']['country'], 'direction': direction, "size_bytes": data_sum, 'device_id': device_id})
            for port, port_details in details['ports'].items():
                for protocol_stack in port_details['protocol_stacks']:
                    layers = protocol_stack['protocol_stack'].split(' - ')
                    protocol_entry = {
                        'size_bytes': size_to_bytes(protocol_stack['total_bytes']),
                        'direction': direction,
                        'device_id': device_id
                    }
                    for i, layer in enumerate(layers):
                        protocol_entry[f'layer_{i+1}'] = layer
                    protocols_data.append(protocol_entry)

    # If same domains receive data, add them to one row
    if domains_data:
        domains_data = pd.DataFrame(domains_data).groupby(['domain', 'direction', 'device_id']).sum().reset_index().to_dict('records')

    if countries_data:
        countries_data = pd.DataFrame(countries_data).groupby(['country', 'direction', 'device_id']).sum().reset_index().to_dict('records')

    return countries_data, ports_data, protocols_data, domains_data, tls_data

# Function to visualize countries by amount of data
def visualize_countries(countries_data, save_path=None):
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

    # Group by name and direction
    df = df.groupby(['country', 'direction', 'device_id']).sum().reset_index()

    # Sort the DataFrame by size_bytes in descending order
    df = df.sort_values(by='size_bytes', ascending=False)

    ## export dataframe as csv
    df.to_csv(os.path.join(save_path, 'countries_plot.csv'), index=False)

    plt.figure(figsize=(10, 6))
    plt.xscale('log')
    plt.xlabel(size_label)
    sns.barplot(data=df, x='size_bytes', y='country', hue='direction', orient='h')
    plt.ylabel('Country')
    plt.title('Countries by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(os.path.join(save_path,'countries_plot.png'))
    else:
        plt.show()

# Function to visualize ports by amount of data
def visualize_ports(ports_data, save_path=None):
    df = pd.DataFrame(ports_data)
    sns.barplot(data=df, x='port', y='size_bytes', hue='direction')
    plt.title('Ports by Amount of Data')

    # Sort the DataFrame by size_bytes in descending order
    df = df.sort_values(by='size_bytes', ascending=False)

    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()

# Function to visualize protocols by amount of data
def visualize_protocols(protocols_data, save_path=None):
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

    # Group by name and direction
    df_highest_layer = df_highest_layer.groupby(['highest_layer', 'direction']).sum().reset_index()

    # Filter out padding and Raw
    df_highest_layer = df_highest_layer[df_highest_layer['highest_layer'] != 'Padding']
    df_highest_layer = df_highest_layer[df_highest_layer['highest_layer'] != 'Raw']

    # Sort the DataFrame by size_bytes in descending order
    df_highest_layer = df_highest_layer.sort_values(by='size_bytes', ascending=False)

    # Export dataframe as csv
    df_highest_layer.to_csv(os.path.join(save_path,'protocols_plot.csv'), index=False)

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df_highest_layer, x='size_bytes', y='highest_layer', hue='direction', orient='h')
    plt.xscale('log')
    plt.xlabel(size_label)
    plt.ylabel('Highest Layer')
    plt.title('Protocols by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(os.path.join(save_path,'protocols_plot.png'))
    else:
        plt.show()

# Function to visualize protocol layers using plotly Parallel Categories Diagram
def visualize_protocol_layers(protocols_data, save_path=None):
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

    # Sort the DataFrame by size_bytes in descending order
    df = df.sort_values(by='size_bytes', ascending=False)

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

## Check if domain is in one of the domain groups
def tag_domain(domain):
    for group_name in DOMAIN_GROUPS.keys():
        if domain in DOMAIN_GROUPS[group_name]:
            return group_name
    for manufacturer_domain in NON_MANUFACTURER_DOMAINS:
        if domain in manufacturer_domain:
            return domain
    for nameserver in get_nameservers(domain):
        for group_name in NAMESERVER_GROUPS.keys():
            for domain in NAMESERVER_GROUPS[group_name]:
                if domain in nameserver:
                    return group_name
    return "[SELF-HOSTED SERVICES]"

## Check if domain is in one of the domain groups
def is_selfhosted(domain):
    if tag_domain(domain) == "[SELF-HOSTED SERVICES]":
        return True
    return False

## Define a function to query the nameservers for a given domain
def get_nameservers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(rdata.target) for rdata in answers]
        return nameservers
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

# Tag and filter domains
def preprocess_domains(domains_data, save_path):
    # Extract TLD from each domain
    domains_data['tld'] = domains_data['domain'].apply(extract_tld)

    # Group by TLD and direction
    tld_counts = domains_data.groupby(['tld', 'direction', 'device_id']).sum().reset_index()

    # Replace common domains with group names
    # First copy TLD to separate column
    tld_counts['tld_orig'] = tld_counts['tld']

    # Group domains using tag_domain-function
    tld_counts['tld'] = tld_counts['tld_orig'].apply(tag_domain)

    # Print separate csv log file of self-hosted service domains
    # Syntax: domain, direction, size_bytes
    with open(os.path.join(save_path, 'self_hosted_services.csv'), 'w') as f:
        ## Iterate all domains that are listed as self-hosted
        for domain in tld_counts.loc[tld_counts['tld_orig'].apply(is_selfhosted), 'tld_orig']:
            f.write(
                f"{domain}, "
                f"{tld_counts.loc[tld_counts['tld_orig'] == domain, 'direction'].values[0]}, "
                f"{tld_counts.loc[tld_counts['tld_orig'] == domain, 'size_bytes'].values[0]}\n"
            )

    # Remove [CDN] and [DNS], as they are not that interesting in this scope
    tld_counts = tld_counts.loc[tld_counts['tld'].apply(lambda x: x not in ['[CDN]', '[DNS]'])]

    return tld_counts

def visualize_domains(domains_data, save_path=None):
    df = pd.DataFrame(domains_data)

    # preprocess domains
    tld_counts = preprocess_domains(df, save_path)

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

    # Sort the DataFrame by size_bytes in descending order
    tld_counts = tld_counts.sort_values(by='size_bytes', ascending=False)

    ## export dataframe as csv
    tld_counts.to_csv(os.path.join(save_path,'domains_plot.csv'), index=False)

    # Plot the data with count of domains for each TLD on the horizontal axis
    plt.figure(figsize=(12, 6))
    sns.barplot(data=tld_counts, x='size_bytes', y='tld', hue='direction', orient='h')
    plt.xlabel(size_label)
    plt.xscale('log')
    plt.ylabel('Domain')
    plt.title('Domains by usage')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(os.path.join(save_path,'domains_plot.png'))
    else:
        plt.show()

def visualize_domains_by_device(domains_data, save_path=None):
    df = pd.DataFrame(domains_data)

    # preprocess domains
    tld_counts = preprocess_domains(df, save_path)

    # Aggregate data
    df_agg = tld_counts.groupby('tld').agg(
        total_bytes_sent=pd.NamedAgg(column='size_bytes', aggfunc=lambda x: x[df['direction'] == 'src'].sum()),
        total_bytes_received=pd.NamedAgg(column='size_bytes', aggfunc=lambda x: x[df['direction'] == 'dst'].sum()),
        num_devices=pd.NamedAgg(column='device_id', aggfunc='nunique')
    ).reset_index()

    # Sort by number of devices and select top 10 domains
    df_top_10 = df_agg.sort_values(by='num_devices', ascending=False).head(20)

    # Create bubble chart
    plt.figure(figsize=(12, 8))
    unique_tlds = df_top_10['tld'].unique()
    colors = plt.cm.viridis([i / (len(unique_tlds) - 1) for i in range(len(unique_tlds))])
    color_dict = dict(zip(unique_tlds, colors))

    scatter = plt.scatter(
        df_top_10['total_bytes_sent'],
        df_top_10['total_bytes_received'],
        s=df_top_10['num_devices'] * 10,  # Adjust size scaling factor as needed
        c=df_top_10['tld'].map(color_dict),  # Map TLDs to colors
        alpha=0.6,
        edgecolors='w',
        linewidth=0.5
    )

    # Add labels and title
    plt.xlabel('Total Bytes Sent')
    plt.ylabel('Total Bytes Received')
    plt.title('Domain Communication Overview')
    plt.xscale('log')
    plt.yscale('log')

    # Add grid lines to illustrate logarithmic scale
    plt.grid(True, which="both", ls="--", linewidth=0.5)

    # Add legend
    for tld, color in color_dict.items():
        plt.scatter([], [], c=[color], label=tld, alpha=0.6, edgecolors='w', linewidth=0.5)
    plt.legend(title='TLD')

    # Save or display the plot
    if save_path:
        plt.savefig(os.path.join(save_path, 'domains_by_device_scatter_plot.png'))
    else:
        plt.show()

    ## Scale num_devices into percentage of total devices
    df_agg['num_devices'] = df_agg['num_devices'] / df_agg['num_devices'].sum() * 100

    # Sort by number of devices
    df_agg = df_agg.sort_values(by='num_devices', ascending=False)

    # Plot strengths
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df_agg, x='num_devices', y='tld', orient='h')
    plt.xlabel("Popularity (%)", fontsize=18)
    plt.ylabel('Domain', fontsize=18)
    plt.xticks(fontsize=15)
    plt.yticks(fontsize=15)
    plt.title('Most popular domains used by devices', fontsize=18)
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    # Save or display the plot
    if save_path:
        plt.savefig(os.path.join(save_path, 'domains_by_device_plot.png'))
    else:
        plt.show()

def visualize_tls_ciphers(tls_data, save_path=None):
    df = pd.DataFrame(tls_data)

    if 'cipher' not in df.columns:
        print("No TLS ciphers found in the data.")
        return

    # Step 1: Split the 'cipher' column by comma
    df['cipher'] = df['cipher'].str.split(',')

    # Step 2: Use explode to create separate rows for each cipher
    df = df.explode('cipher')

    # Step 3: Strip whitespace characters from each cipher value
    df['cipher'] = df['cipher'].str.strip()

    # Step 4: Group by the 'cipher' column and sum the 'size_bytes'
    df = df.groupby('cipher', as_index=False)['size_bytes'].sum()

    # Use https://ciphersuite.info to evaluate ciphersuite strength
    for ciphersuite in df['cipher']:
        URL = "https://ciphersuite.info/api/cs/" + ciphersuite
        response = requests.get(URL)
        if response.status_code == 200:
            data = response.json()
            df.loc[df['cipher'] == ciphersuite, 'security'] = data[ciphersuite]['security']
        else:
            df.loc[df['cipher'] == ciphersuite, 'security'] = 'Unknown'

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

    # Sort the DataFrame by size_bytes in descending order
    df = df.sort_values(by='size_bytes', ascending=False)

    # Convert size to percentage of usage
    df['usage'] = df['size_bytes'] / df['size_bytes'].sum() * 100

    ## export dataframe as csv
    df.to_csv(os.path.join(save_path,'tls_ciphers_plot.csv'), index=False)

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df, x='size_bytes', y='cipher', orient='h')
    plt.xscale('log')
    plt.xlabel("Usage (%)")
    plt.ylabel('Cipher')
    plt.title('TLS Ciphers by Popularity', fontsize=18)
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(os.path.join(save_path,'tls_ciphers_plot.png'))
    else:
        plt.show()

    # Group by security level
    df = df.groupby('security', as_index=False)['size_bytes'].sum()

    # Convert bytes to percentage of total
    df['usage'] = df['size_bytes'] / df['size_bytes'].sum() * 100

    # Sort the DataFrame by size_bytes in descending order
    df = df.sort_values(by='usage', ascending=False)

    # Plot strengths
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df, x='usage', y='security', orient='h')
    plt.xlabel("Usage (%)", fontsize=18)
    plt.ylabel('Strength', fontsize=18)
    plt.xticks(fontsize=15)
    plt.yticks(fontsize=15)
    plt.title('TLS Cipher strength (ciphersuite.info) by Percentage of Data', fontsize=18)
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(os.path.join(save_path,'tls_ciphers_strength_plot.png'))
    else:
        plt.show()

def visualize_tls_versions(tls_data, save_path=None):
    df = pd.DataFrame(tls_data)

    if 'version' not in df.columns:
        print("No TLS versions found in the data.")
        return

    # If several ciphers are split with comma in one row, split them
    ## TODO: Fix this in data aggregation, there is a bug in pcap parsing

    # Step 1: Split the 'cipher' column by comma
    df['version'] = df['version'].str.split(',')

    # Step 2: Use explode to create separate rows for each cipher
    df = df.explode('version')

    # Step 3: Strip whitespace characters from each cipher value
    df['version'] = df['version'].str.strip()

    # Step 4: Group by the 'cipher' column and sum the 'size_bytes'
    df = df.groupby('version', as_index=False)['size_bytes'].sum()

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

    # Sort the DataFrame by size_bytes in descending order
    df = df.sort_values(by='size_bytes', ascending=False)

    ## export dataframe as csv
    df.to_csv(os.path.join(save_path,'tls_versions_plot.csv'), index=False)

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df, x='size_bytes', y='version', orient='h')
    plt.xscale('log')
    plt.xlabel(size_label)
    plt.ylabel('TLS Version')
    plt.title('TLS Versions by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(os.path.join(save_path, 'tls_versions_plot.png'))
    else:
        plt.show()

@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--save_path', type=click.Path(), help='Path to save the visualizations')
@click.option('--recursive_search', is_flag=True, default=False, help='Do recursive search of json files in given path')
def visualize_reports(path, save_path, recursive_search):
    def fetch_all_json_files(path, report_files=[]):
        # Determine if the path is a directory or a file
        if os.path.isdir(path):
            report_files.extend(glob(os.path.join(path, '*.json')))
            ## Check if there are any subdirectories
            subdirectories = [f for f in glob(os.path.join(path, '*')) if os.path.isdir(f)]
            if subdirectories and recursive_search:
                for subdirectory in subdirectories:
                    report_files.extend(fetch_all_json_files(subdirectory, report_files))
        else:
            report_files = [path]
        return report_files

    report_files = fetch_all_json_files(path)
    assert len(report_files) > 0, "No report .json-files found in the specified path."

    all_countries_data = []
    all_ports_data = []
    all_protocols_data = []
    all_domains_data = []
    all_tls_data = []

    for i, report_file in enumerate(report_files):
        with open(report_file, 'r') as file:
            report = file.read()
            countries_data, ports_data, protocols_data, domains_data, tls_data = parse_report(report, device_id = i)
            all_countries_data.extend(countries_data)
            all_ports_data.extend(ports_data)
            all_protocols_data.extend(protocols_data)
            all_domains_data.extend(domains_data)
            all_tls_data.extend(tls_data)

    # check if save_path exists, create if not
    if save_path:
        if not os.path.exists(save_path):
            os.makedirs(save_path)

    # Visualize aggregated data
    visualize_countries(all_countries_data, save_path=save_path)
    visualize_protocols(all_protocols_data, save_path=save_path)
    #visualize_protocol_layers(all_protocols_data)
    visualize_domains(all_domains_data, save_path=save_path)
    visualize_tls_versions(all_tls_data, save_path=save_path)
    visualize_tls_ciphers(all_tls_data, save_path=save_path)
    visualize_domains_by_device(all_domains_data, save_path=save_path)

if __name__ == '__main__':
    visualize_reports()