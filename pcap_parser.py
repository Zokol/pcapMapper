### PcapParser
# Description: This class is used to parse pcap into pandas dataframe, using tshark
# Input: pcap file
# Output: pandas dataframe
# Dependencies: tshark, pandas

import subprocess
import pandas as pd
import os

class PcapParser:
    def __init__(self, pcap_file, fields=None, filter=None):
        self.pcap_file = pcap_file
        self.pcap_dataframe = None
        self.pcap_fields = None

    def parse_pcap(self):
        # Check if the pcap file exists
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"{self.pcap_file} not found")

        # If fields are not provided, use default fields
        if self.pcap_fields is None:
            self.pcap_fields = ["frame.number", "frame.time", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.seq", "tcp.ack", "tcp.flags", "tcp.window_size", "tcp.analysis.ack_rtt", "tcp.analysis.initial_rtt", "tcp.analysis.ack_rtt", "tcp.analysis.bytes_in_flight

        # Use tshark to parse the pcap file
        tshark_cmd = ["tshark", "-r", self.pcap_file, "-T", "fields"]
        tshark_cmd.extend(["-e", ",".join(self.pcap_fields)])
        if self.filter is not None:
            tshark_cmd.extend(["-Y", self.filter])

        # Run the tshark command
        tshark_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tshark_out, tshark_err = tshark_proc.communicate()

        # Check if tshark command was successful
        if tshark_proc.returncode != 0:
            raise RuntimeError(f"Error running tshark: {tshark_err.decode()}")

        # Convert tshark output to pandas dataframe
        self.pcap_dataframe = pd.read_csv(pd.compat.StringIO(tshark_out.decode()), sep=",")

    def get_dataframe(self):
        return self.pcap_dataframe

    def run(self):
        self.parse_pcap()
        return self.get_dataframe()