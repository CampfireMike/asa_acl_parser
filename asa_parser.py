import re
import xlwt
import sys
from collections import defaultdict

# Function to parse the ASA configuration
def parse_asa_config(config_file):
    with open(config_file, 'r') as f:
        config = f.read()

    access_lists = defaultdict(list)
    current_acl_name = None

    # Regular expressions for parsing access-list entries
    acl_name_pattern = re.compile(r"^access-list (\S+)")
    acl_entry_pattern = re.compile(r"^\s*(permit|deny)\s+(\S+)\s+(\S+)\s+(\S+)")
    object_group_pattern = re.compile(r"^object-group (\S+)\s*")
    object_pattern = re.compile(r"^object (\S+)\s+(\S+)\s+(\S+)")

    # Loop through each line in the configuration file
    for line in config.splitlines():
        line = line.strip()

        # Identify access-list name
        acl_match = acl_name_pattern.match(line)
        if acl_match:
            current_acl_name = acl_match.group(1)
            continue

        # Identify ACL entries (permit/deny)
        acl_entry_match = acl_entry_pattern.match(line)
        if acl_entry_match:
            action, source, destination, service = acl_entry_match.groups()

            # Resolve object-groups
            source = resolve_objects(source, config)
            destination = resolve_objects(destination, config)
            service = resolve_objects(service, config)

            # Add the entry to the access-list
            access_lists[current_acl_name].append([action, source, destination, service])

        # Object-group processing
        object_group_match = object_group_pattern.match(line)
        if object_group_match:
            group_name = object_group_match.group(1)
            access_lists[group_name]  # Just to ensure it's created

        # Handle object definitions
        object_match = object_pattern.match(line)
        if object_match:
            object_name, object_type, value = object_match.groups()
            access_lists[object_name].append(value)

    return access_lists

# Function to resolve objects or object-groups into their actual values
def resolve_objects(identifier, config):
    # If it's an object or group, expand it
    if identifier.startswith("obj_") or identifier.startswith("group"):
        expanded_values = []
        object_match = re.compile(r"^object (\S+)\s+(\S+)\s+(\S+)")
        for line in config.splitlines():
            if object_match.match(line.strip()):
                expanded_values.append(line.strip())
        return '\n'.join(expanded_values)
    return identifier

# Function to create Excel file
def create_excel(access_lists, output_file):
    # Initialize Excel workbook
    wb = xlwt.Workbook()
    ws = wb.add_sheet('Access List')

    # Set up column headers
    headers = ['Access List', 'Source', 'Destination', 'Service']
    for col_num, header in enumerate(headers):
        ws.write(0, col_num, header)

    row = 1
    # Write each access list entry to the spreadsheet
    for acl_name, entries in access_lists.items():
        for entry in entries:
            source, destination, service = entry[1], entry[2], entry[3]
            # Write ACL name and other fields
            ws.write(row, 0, acl_name)
            ws.write(row, 1, source)
            ws.write(row, 2, destination)
            ws.write(row, 3, service)
            row += 1

    # Save the Excel file
    wb.save(output_file)

# Main function to parse the config and generate the Excel
def main():
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <input_config_file>")
        sys.exit(1)

    config_file = sys.argv[1]  # Get the input file from command-line argument
    output_file = 'access_list.xlsx'  # Specify the output Excel file path

    # Parse the ASA configuration file
    access_lists = parse_asa_config(config_file)

    # Create an Excel file with the parsed data
    create_excel(access_lists, output_file)

# Run the main function
if __name__ == '__main__':
    main()
