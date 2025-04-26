import re
import openpyxl
from openpyxl import Workbook
import argparse
import os

# Function to parse the object/group names and their contents
def parse_object_group(obj_name, config):
    obj_contents = []
    pattern = re.compile(
        rf"(object-group|object) (network|service) {re.escape(obj_name)}\n((?: .*\n)*)",
        re.IGNORECASE
    )
    match = pattern.search(config)
    if match:
        lines = match.group(3).strip().splitlines()
        for line in lines:
            obj_contents.append(line.strip())
    return obj_contents

# Function to parse a single line in the access-list
def parse_acl_line(line, config):
    acl_data = {}

    # Access-list name
    acl_name_match = re.match(r"access-list (\S+)", line)
    acl_data['Access-List'] = acl_name_match.group(1) if acl_name_match else ""

    tokens = line.split()
    try:
        # Typically: access-list NAME extended permit tcp SRC DST EQ PORT
        src_index = tokens.index("extended") + 3
        src = tokens[src_index]
        dst = tokens[src_index + 1]
        svc = ' '.join(tokens[src_index + 2:]) if len(tokens) > src_index + 2 else ""

        # Source
        if src.startswith("object-group") or src.startswith("object"):
            obj_name = tokens[src_index + 1]
            acl_data['Source Object'] = obj_name
            acl_data['Source Object Details'] = ', '.join(parse_object_group(obj_name, config))
        else:
            acl_data['Source IP/Subnet'] = src

        # Destination
        if dst.startswith("object-group") or dst.startswith("object"):
            dst_obj_index = src_index + 3 if 'object' in src else src_index + 2
            obj_name = tokens[dst_obj_index]
            acl_data['Destination Object'] = obj_name
            acl_data['Destination Object Details'] = ', '.join(parse_object_group(obj_name, config))
        else:
            acl_data['Destination IP/Subnet'] = dst

        # Service
        acl_data['Service Port'] = svc

    except (ValueError, IndexError):
        # Could not parse as expected
        pass

    return acl_data

# Function to parse the entire Cisco ASA config
def parse_asa_config(config_file):
    with open(config_file, 'r') as f:
        config = f.read()

    wb = Workbook()
    ws = wb.active
    ws.title = "Access Lists"

    headers = [
        'Access-List',
        'Source IP/Subnet',
        'Destination IP/Subnet',
        'Service Port',
        'Source Object',
        'Source Object Details',
        'Destination Object',
        'Destination Object Details'
    ]
    ws.append(headers)

    # Parse all access-list lines
    acl_lines = [line for line in config.splitlines() if line.strip().startswith("access-list")]
    for line in acl_lines:
        acl_data = parse_acl_line(line.strip(), config)
        ws.append([
            acl_data.get('Access-List', ''),
            acl_data.get('Source IP/Subnet', ''),
            acl_data.get('Destination IP/Subnet', ''),
            acl_data.get('Service Port', ''),
            acl_data.get('Source Object', ''),
            acl_data.get('Source Object Details', ''),
            acl_data.get('Destination Object', ''),
            acl_data.get('Destination Object Details', ''),
        ])

    # Save Excel
    base_name = os.path.splitext(os.path.basename(config_file))[0]
    output_file = f"{base_name}_parsed_acl.xlsx"
    wb.save(output_file)
    print(f"Parsing complete! Excel file '{output_file}' created.")

# Main function with CLI
def main():
    parser = argparse.ArgumentParser(description="Parse Cisco ASA ACL config into Excel.")
    parser.add_argument("filename", help="Path to ASA config file")
    args = parser.parse_args()

    if not os.path.isfile(args.filename):
        print(f"Error: File '{args.filename}' does not exist.")
        return

    parse_asa_config(args.filename)

if __name__ == '__main__':
    main()
