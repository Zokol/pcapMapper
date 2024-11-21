import json
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import seaborn as sns
from glob import glob
import tldextract
import os
import click

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

    plt.figure(figsize=(10, 5))
    plt.xscale('log')
    plt.xlabel(size_label)
    sns.barplot(data=df, x='size_bytes', y='country', hue='direction', orient='h')
    plt.ylabel('Country')
    plt.title('Countries by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
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


    # Sort the DataFrame by size_bytes in descending order
    df_highest_layer = df_highest_layer.sort_values(by='size_bytes', ascending=False)

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 5))
    sns.barplot(data=df_highest_layer, x='size_bytes', y='highest_layer', hue='direction', orient='h')
    plt.xscale('log')
    plt.xlabel(size_label)
    plt.ylabel('Highest Layer')
    plt.title('Protocols by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
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

def visualize_domains(domains_data, save_path=None):
    df = pd.DataFrame(domains_data)

    # Extract TLD from each domain
    df['tld'] = df['domain'].apply(extract_tld)

    # Group by TLD and direction
    tld_counts = df.groupby(['tld', 'direction', 'device_id']).sum().reset_index()

    # Group manufacturer-owned (not amazon, cloudflare, iotcplatform or ntp) domains into single group
    non_manufacturer_domains = [
        'amazonaws.com',
        'cloudflare.net',
        'ntp.org',
        'google.com',
        'iotcplatform.com',
        'klarna.net',
        'microsoft.com',
        'lokalise.com.',
        'apple.com',
        'akamai.net.',
        'fastly.net',
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
        'app-analytics-services.com.',
        'app-measurement.com.',
        'split.io.',
        'firebase.io.com',
        'leanplum.com',
        'branch.io',
        'akadns.net',
        'apple-dns.net',
        'googleapis.com',
        'aaplimg.com',
        'akamai.net',
        'cloudfront.net',
        'akamaiedge.net',
        'lokalise.com',
        'privacy-center.org',
        'app-analytics-services.com',
        'gstatic.com',
        'lokalise.co',
        'cloudflare.com',
        'app-measurement.com',
        'firebaseio.com',
        'phicdn.net',
        'shipup.co',
        'emb-api.com',
        'one.one'
    ]

    # Print separate csv log file of self-hosted service domains
    # Syntax: domain, direction, size_bytes
    with open('self_hosted_services.csv', 'w') as f:
        for domain in tld_counts.loc[tld_counts['tld'].apply(lambda x: x not in non_manufacturer_domains), 'tld']:
            f.write(
                f"{domain}, "
                f"{tld_counts.loc[tld_counts['tld'] == domain, 'direction'].values[0]}, "
                f"{tld_counts.loc[tld_counts['tld'] == domain, 'size_bytes'].values[0]}\n"
            )

    tld_counts.loc[tld_counts['tld'].apply(lambda x: x not in non_manufacturer_domains), 'tld'] = '[SELF-HOSTED SERVICES]'

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

    # Plot the data with count of domains for each TLD on the horizontal axis
    plt.figure(figsize=(12, 6))
    sns.barplot(data=tld_counts, x='size_bytes', y='tld', hue='direction', orient='h')
    plt.xlabel(size_label)
    plt.xscale('log')
    plt.ylabel('Top-Level Domain (TLD)')
    plt.title('Domains Grouped by TLD')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()

def visualize_domains_by_device(domains_data, save_path=None):
    df = pd.DataFrame(domains_data)

    # Extract TLD from each domain
    df['tld'] = df['domain'].apply(extract_tld)

    # Group by TLD and direction
    tld_counts = df.groupby(['tld', 'direction', 'device_id']).sum().reset_index()

    domain_groups = {
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
        ],
        "[GOOGLE FIREBASE]": [
            'app-analytics-services.com.',
            'app-measurement.com.',
            'firebase.io.com',
            'firebaseio.com',
            'google.com',
            'googleapis.com',
        ],
        "[DNS]": [
            'akadns.net',
            'apple-dns.net',
            'one.one'
        ]
    }

    # Group manufacturer-owned (not amazon, cloudflare, iotcplatform or ntp) domains into single group
    non_manufacturer_domains = [
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
        'app-analytics-services.com.',
        'app-measurement.com.',
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
        'one.one'
    ]

    tld_counts.loc[tld_counts['tld'].apply(lambda x: x not in non_manufacturer_domains), 'tld'] = '[SELF-HOSTED SERVICES]'
    for group, domains in domain_groups.items():
        tld_counts.loc[tld_counts['tld'].apply(lambda x: x in domains), 'tld'] = group

    # Print separate csv log file of self-hosted service domains
    # Syntax: domain, direction, size_bytes
    with open('self_hosted_services_by_device.csv', 'w') as f:
        for domain in tld_counts.loc[tld_counts['tld'].apply(lambda x: x not in non_manufacturer_domains), 'tld']:
            f.write(
                f"{domain}, "
                f"{tld_counts.loc[tld_counts['tld'] == domain, 'direction'].values[0]}, "
                f"{tld_counts.loc[tld_counts['tld'] == domain, 'size_bytes'].values[0]}\n"
            )

    # Aggregate data
    df_agg = tld_counts.groupby('tld').agg(
        total_bytes_sent=pd.NamedAgg(column='size_bytes', aggfunc=lambda x: x[df['direction'] == 'src'].sum()),
        total_bytes_received=pd.NamedAgg(column='size_bytes', aggfunc=lambda x: x[df['direction'] == 'dst'].sum()),
        num_devices=pd.NamedAgg(column='device_id', aggfunc='nunique')
    ).reset_index()

    # Sort by number of devices and select top 10 domains
    df_top_10 = df_agg.sort_values(by='num_devices', ascending=False).head(10)

    # Create bubble chart
    fig = px.scatter(
        df_top_10,
        x='total_bytes_sent',
        y='total_bytes_received',
        size='num_devices',
        color='tld',
        hover_name='tld',
        log_x=True,
        log_y=True,
        size_max=60,
        labels={
            'total_bytes_sent': 'Total Bytes Sent',
            'total_bytes_received': 'Total Bytes Received',
            'num_devices': 'Number of Devices'
        },
        title='Domain Communication Overview'
    )

    # Add grid lines to illustrate logarithmic scale
    fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='LightGray')
    fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='LightGray')

    if save_path:
        fig.write_image(save_path)
    else:
        fig.show()

def visualize_tls_ciphers(tls_data, save_path=None):
    df = pd.DataFrame(tls_data)

    # If several ciphers are split with comma in one row, split them
    ## TODO: Fix this in data aggregation, there is a bug in pcap parsing

    # Step 1: Split the 'cipher' column by comma
    df['cipher'] = df['cipher'].str.split(',')

    # Step 2: Use explode to create separate rows for each cipher
    df = df.explode('cipher')

    # Step 3: Strip whitespace characters from each cipher value
    df['cipher'] = df['cipher'].str.strip()

    # Step 4: Group by the 'cipher' column and sum the 'size_bytes'
    df = df.groupby('cipher', as_index=False)['size_bytes'].sum()

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

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 5))
    sns.barplot(data=df, x='size_bytes', y='cipher', orient='h')
    plt.xscale('log')
    plt.xlabel(size_label)
    plt.ylabel('Cipher')
    plt.title('TLS Ciphers by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()

def visualize_tls_versions(tls_data, save_path=None):
    df = pd.DataFrame(tls_data)

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

    # Plot the data with size_bytes on the horizontal axis
    plt.figure(figsize=(10, 5))
    sns.barplot(data=df, x='size_bytes', y='version', orient='h')
    plt.xscale('log')
    plt.xlabel(size_label)
    plt.ylabel('TLS Version')
    plt.title('TLS Versions by Amount of Data')
    plt.grid(True, which="both", ls="--", linewidth=0.5)
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
    else:
        plt.show()

@click.command()
@click.argument('path', type=click.Path(exists=True))
def visualize_reports(path):
    # Determine if the path is a directory or a file
    if os.path.isdir(path):
        report_files = glob(os.path.join(path, '*.json'))
    else:
        report_files = [path]

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

    # Visualize aggregated data
    visualize_countries(all_countries_data, save_path=os.path.join(path, 'countries_plot.png'))
    visualize_protocols(all_protocols_data, save_path=os.path.join(path, 'protocols_plot.png'))
    #visualize_protocol_layers(all_protocols_data)
    visualize_domains(all_domains_data, save_path=os.path.join(path, 'domains_plot.png'))
    visualize_tls_versions(all_tls_data, save_path=os.path.join(path, 'tls_versions_plot.png'))
    visualize_tls_ciphers(all_tls_data, save_path=os.path.join(path, 'tls_ciphers_plot.png'))
    visualize_domains_by_device(all_domains_data, save_path=os.path.join(path, 'domains_by_device_plot.png'))

if __name__ == '__main__':
    visualize_reports()