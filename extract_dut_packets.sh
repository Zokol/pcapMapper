#!/bin/bash

# Check if a filter type, address, output file name, and target folder are provided
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
  echo "Usage: $0 <filter_type: ip|mac> <address> <output_file> <target_folder>"
  exit 1
fi

FILTER_TYPE=$1
ADDRESS=$2
OUTPUT_FILE=$3
TARGET_FOLDER=$4
TEMP_FOLDER="/tmp/pcap_filter_$(date +%s)"

# Create a temp-folder
mkdir -p "$TEMP_FOLDER"

# Determine the tshark filter expression based on the filter type
if [ "$FILTER_TYPE" == "ip" ]; then
  FILTER_EXPR="ip.addr == $ADDRESS"
elif [ "$FILTER_TYPE" == "mac" ]; then
  FILTER_EXPR="eth.addr == $ADDRESS"
else
  echo "Invalid filter type. Use 'ip' or 'mac'."
  exit 1
fi

# Iterate all pcap files in the target folder
for pcap_file in "$TARGET_FOLDER"/*.pcap*; do
  if [[ -f $pcap_file ]]; then
    output_file="$TEMP_FOLDER/filtered_$(basename $pcap_file)"
    # Run tshark filter for each file
    tshark -nnr "$pcap_file" -Y "$FILTER_EXPR" -w "$output_file"
  fi
done

# Merge all pcaps in temp-folder using mergecap
if ls "$TEMP_FOLDER"/*.pcap* 1> /dev/null 2>&1; then
  mergecap -w "$OUTPUT_FILE" "$TEMP_FOLDER"/*.pcap*
  echo "Filtered and merged pcap files are saved in $OUTPUT_FILE"
else
  echo "No pcap files to merge in $TEMP_FOLDER"
fi

# Clean up temp-folder
rm -rf "$TEMP_FOLDER"