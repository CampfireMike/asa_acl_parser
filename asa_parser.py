import re
import sys
import pandas as pd
from collections import defaultdict
from itertools import product

def parse_asa_acl(config_file_path, output_excel_path):
    data = []
    network_objects = {}
    service_objects = {}
    object_groups = defaultdict(list)
    service_groups = defaultdict(list)

    with open(config_file_path, 'r') as file:
        lines = [line.strip() for line in file.readlines()]

    # Parse all object and group definitions first
    current_object = None
    current_group = None
    group_type = None

    for line in lines:
        if line.startswith('object network'):
            current_object = line.split()[-1]
        elif current_object:
            if line.startswith('host'):
                network_objects[current_object] = [line.split()[1]]
            elif line.startswith('subnet'):
                parts = line.split()
                network_objects[current_object] = [f"{parts[1]} {parts[2]}"]
            elif line in ('exit', '!'):
                current_object = None

        elif line.startswith('object service'):
            current_object = line.split()[-1]
        elif current_object and line.startswith('service'):
            parts = line.split(maxsplit=1)
            service_objects[current_object] = [parts[1]] if len(parts) > 1 else []
        elif current_object and line in ('exit', '!'):
            current_object = None

        elif line.startswith('object-group network'):
            current_group = line.split()[-1]
            group_type = 'network'
        elif line.startswith('object-group service'):
            current_group = line.split()[-1]
            group_type = 'service'

        elif current_group:
            if line in ('exit', '!'):
                current_group = None
            elif group_type == 'network':
                if line.startswith('host'):
                    object_groups[current_group].append(line.split()[1])
                elif line.startswith('network-object'):
                    parts = line.split()
                    if parts[1] == 'host':
                        object_groups[current_group].append(parts[2])
                    else:
                        object_groups[current_group].append(" ".join(parts[1:]))
            elif group_type == 'service':
                service_groups[current_group].append(line)

    # Helper to expand object/entity
    def resolve_entity(token_type, token):
        if token_type == 'any':
            return ['any']
        elif token_type == 'host':
            return [token]
        elif token_type == 'object-group':
            return object_groups.get(token, [token])
        elif token_type == 'object':
            return network_objects.get(token, [token])
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', token):
            return [token]
        return [token]

    def resolve_service(token_type, token):
        if token_type == 'object-group':
            return service_groups.get(token, [token])
        elif token_type == 'object':
            return service_objects.get(token, [token])
        return [token]

    acl_pattern = re.compile(r'^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.*)$')

    for line in lines:
        match = acl_pattern.match(line)
        if not match:
            continue

        _, action, protocol, rest = match.groups()
        tokens = rest.split()

        try:
            # Parse source
            src_type = tokens[0]
            src_token = tokens[1] if src_type in ('object', 'object-group') else tokens[0]
            src_items = resolve_entity(src_type, src_token)
            consumed = 2 if src_type in ('object', 'object-group') else 1

            # Parse destination
            tokens = tokens[consumed:]
            dst_type = tokens[0]
            dst_token = tokens[1] if dst_type in ('object', 'object-group') else tokens[0]
            dst_items = resolve_entity(dst_type, dst_token)
            consumed = 2 if dst_type in ('object', 'object-group') else 1

            # Parse service
            tokens = tokens[consumed:]
            if tokens:
                svc_type = tokens[0]
                svc_token = tokens[1] if svc_type in ('object', 'object-group') else svc_type
                svc_items = resolve_service(svc_type, svc_token)
            else:
                svc_items = ['']

            for src, dst, svc in product(src_items, dst_items, svc_items):
                data.append({
                    'Source': src,
                    'Destination': dst,
                    'Destination Service': svc
                })

        except Exception as e:
            print(f"Failed to parse line: {line}\nError: {e}")

    df = pd.DataFrame(data)
    df.to_excel(output_excel_path, index=False)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <asa_config_file>")
        sys.exit(1)

    config_file_path = sys.argv[1]
    output_excel_path = "access_list.xlsx"
    parse_asa_acl(config_file_path, output_excel_path)
    print(f"Parsed ACL entries saved to {output_excel_path}")
