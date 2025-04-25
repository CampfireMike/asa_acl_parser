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
            group_type = 'network'
        elif line.startswith('object service'):
            current_object = line.split()[-1]
            group_type = 'service'
        elif current_object:
            if group_type == 'network':
                if line.startswith('host'):
                    network_objects[current_object] = [line.split()[1]]
                elif line.startswith('subnet'):
                    parts = line.split()
                    network_objects[current_object] = [f"{parts[1]} {parts[2]}"]
            elif group_type == 'service' and line.startswith('service'):
                parts = line.split(maxsplit=1)
                service_objects[current_object] = [parts[1]] if len(parts) > 1 else []
            if line in ('exit', '!'):
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

    def resolve_entity(token):
        if token == 'any':
            return ['any'], 'any'
        elif token in object_groups:
            return object_groups[token], token
        elif token in network_objects:
            return network_objects[token], token
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', token):
            return [token], token
        return [token], token

    def resolve_service(tokens):
        if not tokens:
            return [''], ''
        if tokens[0] in ('object', 'object-group'):
            obj_name = tokens[1]
            if tokens[0] == 'object-group':
                return service_groups.get(obj_name, [obj_name]), obj_name
            else:
                return service_objects.get(obj_name, [obj_name]), obj_name
        elif tokens[0] in ['eq', 'gt', 'lt', 'range', 'neq']:
            return [" ".join(tokens)], " ".join(tokens)
        return [" ".join(tokens)], " ".join(tokens)

    acl_pattern = re.compile(r'^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.*)$')

    for line in lines:
        match = acl_pattern.match(line)
        if not match:
            continue

        acl_name, action, protocol, rest = match.groups()
        tokens = rest.split()
        idx = 0

        # Service may appear first
        service_ref = ''
        service_tokens = []
        if tokens[0] in ('object', 'object-group') and tokens[1] in service_objects or tokens[1] in service_groups:
            service_tokens = tokens[0:2]
            idx += 2
        elif tokens[0] in ['eq', 'gt', 'lt', 'range', 'neq']:
            service_tokens = tokens[0:3] if len(tokens) > 2 else tokens[0:2]
            idx += len(service_tokens)

        service_vals, service_ref = resolve_service(service_tokens)

        # Source
        src_token = tokens[idx]
        idx += 1
        if src_token in ('object', 'object-group'):
            src_ref = tokens[idx]
            src_vals, src_ref = resolve_entity(src_ref)
            idx += 1
        elif src_token == 'host':
            src_ref = tokens[idx]
            src_vals, src_ref = [src_ref], 'host'
            idx += 1
        else:
            src_vals, src_ref = resolve_entity(src_token)

        # Destination
        dst_token = tokens[idx]
        idx += 1
        if dst_token in ('object', 'object-group'):
            dst_ref = tokens[idx]
            dst_vals, dst_ref = resolve_entity(dst_ref)
            idx += 1
        elif dst_token == 'host':
            dst_ref = tokens[idx]
            dst_vals, dst_ref = [dst_ref], 'host'
            idx += 1
        else:
            dst_vals, dst_ref = resolve_entity(dst_token)

        for src, dst, svc in product(src_vals, dst_vals, service_vals):
            data.append({
                'ACL Name': acl_name,
                'Source Object/Group': src_ref,
                'Source': src,
                'Destination Object/Group': dst_ref,
                'Destination': dst,
                'Service Object/Group': service_ref,
                'Destination Service': svc
            })

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
