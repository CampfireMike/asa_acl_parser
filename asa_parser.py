import re
import pandas as pd
from collections import defaultdict

def parse_asa_acl(config_file_path, output_excel_path):
    data = []
    object_groups = defaultdict(list)
    service_groups = defaultdict(list)
    object_definitions = {}
    service_objects = {}

    with open(config_file_path, 'r') as file:
        lines = file.readlines()

    # First pass: collect object-group and object definitions
    current_group = None
    group_type = None
    current_object = None
    current_service_object = None
    for line in lines:
        line = line.strip()

        if line.startswith("object-group network"):
            current_group = line.split()[-1]
            group_type = "network"
        elif line.startswith("object-group service"):
            parts = line.split()
            current_group = parts[2]
            group_type = "service"
        elif line.startswith("object network"):
            current_object = line.split()[-1]
        elif line.startswith("object service"):
            current_service_object = line.split()[-1]
        elif current_group:
            if line.startswith("object-group") or line == "exit" or line == "!":
                current_group = None
                group_type = None
            elif group_type == "network":
                if line.startswith("host"):
                    object_groups[current_group].append(line.split()[1])
                elif re.match(r'^\d+\.\d+\.\d+\.\d+', line):
                    object_groups[current_group].append(line)
                elif line.startswith("network-object"):
                    tokens = line.split()
                    if tokens[1] == 'host':
                        object_groups[current_group].append(tokens[2])
                    else:
                        object_groups[current_group].append(" ".join(tokens[1:]))
            elif group_type == "service":
                tokens = line.split()
                if tokens:
                    service_groups[current_group].append(" ".join(tokens))
        elif current_object:
            if line.startswith("host"):
                object_definitions[current_object] = line.split()[1]
            elif line.startswith("subnet"):
                object_definitions[current_object] = line.split()[1] + ' ' + line.split()[2]
            elif line == "exit" or line == "!":
                current_object = None
        elif current_service_object:
            if line.startswith("service"):
                tokens = line.split()
                service_objects[current_service_object] = " ".join(tokens[1:])
            elif line == "exit" or line == "!":
                current_service_object = None

    # Second pass: parse access-lists
    acl_pattern = re.compile(r'^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.+)$')

    for line in lines:
        line = line.strip()
        match = acl_pattern.match(line)
        if match:
            acl_name, action, protocol, rest = match.groups()
            tokens = rest.split()

            def parse_entity(tokens):
                if tokens[0] == 'any':
                    return ['any'], 1
                elif tokens[0] == 'host':
                    return [tokens[1]], 2
                elif tokens[0] in object_groups:
                    return object_groups[tokens[0]], 1
                elif tokens[0] in object_definitions:
                    return [object_definitions[tokens[0]]], 1
                elif re.match(r'^\d+\.\d+\.\d+\.\d+$', tokens[0]):
                    return [tokens[0] + ' ' + tokens[1]], 2
                else:
                    return [tokens[0]], 1

            try:
                src, consumed1 = parse_entity(tokens)
                tokens = tokens[consumed1:]
                dst, consumed2 = parse_entity(tokens)
                tokens = tokens[consumed2:]

                if tokens:
                    if tokens[0] in service_groups:
                        service = service_groups[tokens[0]]
                    elif tokens[0] in service_objects:
                        service = [service_objects[tokens[0]]]
                    else:
                        service = [" ".join(tokens)]
                else:
                    service = ['']

                data.append({
                    'Source': ", ".join(src),
                    'Destination': ", ".join(dst),
                    'Destination Service': ", ".join(service)
                })
            except Exception as e:
                print(f"Error parsing line: {line}\n{e}")

    df = pd.DataFrame(data)
    df.to_excel(output_excel_path, index=False)

if __name__ == "__main__":
    config_file_path = "asa_config.txt"
    output_excel_path = "access_list.xlsx"
    parse_asa_acl(config_file_path, output_excel_path)
    print(f"Parsed ACL entries saved to {output_excel_path}")
