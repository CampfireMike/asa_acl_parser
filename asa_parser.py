import re
import argparse
import os
from openpyxl import Workbook


def parse_network_object_groups(config):
    object_groups = {}
    current_group = None
    collecting = False

    lines = config.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("object-group network"):
            current_group = line.split()[-1]
            object_groups[current_group] = []
            collecting = True
        elif collecting:
            if line.startswith("network-object"):
                parts = line.split()
                if "host" in parts:
                    ip = parts[-1] + "/32"
                else:
                    ip = f"{parts[1]}/{mask_to_cidr(parts[2])}"
                object_groups[current_group].append(ip)
            elif line.startswith("group-object"):
                object_groups[current_group].append("GROUP:" + line.split()[-1])
            elif line.startswith("object-group") or line.startswith("object") or line == "":
                collecting = False

    return object_groups


def parse_service_object_groups(config):
    service_groups = {}
    current_group = None
    collecting = False

    lines = config.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("object-group service"):
            current_group = line.split()[2]
            service_groups[current_group] = []
            collecting = True
        elif collecting:
            if line.startswith("port-object"):
                parts = line.split()
                if parts[1] == "range":
                    ports = f"{parts[2]}-{parts[3]}"
                else:
                    ports = parts[1]
                service_groups[current_group].append(ports)
            elif line.startswith("group-object"):
                service_groups[current_group].append("GROUP:" + line.split()[-1])
            elif line.startswith("object-group") or line == "":
                collecting = False

    return service_groups


def mask_to_cidr(mask):
    return sum(bin(int(x)).count('1') for x in mask.split('.'))


def parse_acl_line(line, net_objects, svc_objects):
    tokens = line.strip().split()
    acl_name = tokens[1]
    try:
        action_index = tokens.index("extended") + 1
        action = tokens[action_index]
        protocol = tokens[action_index + 1]

        current = action_index + 2

        def parse_address():
            nonlocal current
            kind = tokens[current]
            if kind == "any":
                current += 1
                return "any", []
            elif kind == "host":
                ip = tokens[current + 1] + "/32"
                current += 2
                return ip, []
            elif kind == "object-group":
                name = tokens[current + 1]
                current += 2
                return name, net_objects.get(name, [])
            elif kind == "object":
                name = tokens[current + 1]
                current += 2
                return name, [name]  # could be refined further
            else:
                ip = tokens[current]
                mask = tokens[current + 1]
                current += 2
                return f"{ip}/{mask_to_cidr(mask)}", []

        src, src_details = parse_address()
        dst, dst_details = parse_address()

        service = ""
        service_details = []

        if current < len(tokens):
            if tokens[current] in ["eq", "range"]:
                service = " ".join(tokens[current:])
                current += len(tokens) - current
            elif tokens[current] in ["object-group", "object"]:
                svc_type = tokens[current]
                svc_name = tokens[current + 1]
                service = svc_name
                if svc_type == "object-group":
                    service_details = svc_objects.get(svc_name, [])
                current += 2

        return {
            "ACL Name": acl_name,
            "Source": src,
            "Source Details": src_details,
            "Destination": dst,
            "Destination Details": dst_details,
            "Service": service,
            "Service Details": service_details
        }
    except Exception as e:
        return None


def write_to_excel(parsed_entries, output_file):
    wb = Workbook()
    ws = wb.active
    ws.title = "Access Lists"

    ws.append([
        "ACL Name",
        "Source",
        "Source Details",
        "Destination",
        "Destination Details",
        "Service",
        "Service Details"
    ])

    for entry in parsed_entries:
        ws.append([
            entry["ACL Name"],
            entry["Source"],
            ", ".join(entry["Source Details"]),
            entry["Destination"],
            ", ".join(entry["Destination Details"]),
            entry["Service"],
            ", ".join(entry["Service Details"])
        ])

    wb.save(output_file)
    print(f"Saved output to {output_file}")


def parse_asa_config_file(filename):
    with open(filename, "r") as f:
        config = f.read()

    net_objects = parse_network_object_groups(config)
    svc_objects = parse_service_object_groups(config)

    parsed = []
    for line in config.splitlines():
        if line.strip().startswith("access-list"):
            entry = parse_acl_line(line, net_objects, svc_objects)
            if entry:
                parsed.append(entry)

    base_name = os.path.splitext(os.path.basename(filename))[0]
    output_file = f"{base_name}_parsed_acl.xlsx"
    write_to_excel(parsed, output_file)


def main():
    parser = argparse.ArgumentParser(description="Parse ASA ACL config to Excel.")
    parser.add_argument("filename", help="Path to ASA config file")
    args = parser.parse_args()

    if not os.path.isfile(args.filename):
        print(f"File '{args.filename}' not found.")
        return

    parse_asa_config_file(args.filename)


if __name__ == "__main__":
    main()
