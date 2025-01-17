import json
import click
import subprocess

def generate_commands_from_json(json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)

    for entry in data:
        dut_name = entry['dut_name']
        mac = entry.get('mac')
        ip = entry.get('ip')
        pcap_file = entry['input-file']
        output_file = entry['report-output-file']

        command = [
            "python3", "main.py",
            "--dut_name", dut_name,
            "--pcap_file", pcap_file,
            "--output", output_file
        ]

        if mac:
            command.extend(["--mac", mac])
        if ip:
            command.extend(["--ip", ip])

        subprocess.run(command)

@click.command()
@click.argument('json_file')
def main(json_file):
    generate_commands_from_json(json_file)

if __name__ == "__main__":
    main()