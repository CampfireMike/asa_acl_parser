import re
import argparse
import os
from openpyxl import Workbook


def mask_to_cidr(mask):
    return sum(bin(int(x)).count('1') for x in mask.split('.'))


def parse_all_object_groups(config):
    net_groups = {}
    svc_groups = {}

    current_group = None
    group_type = None
    collecting = False

    lines = config.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("object-group network"):
            current_group = line.split()[2]
            group_type = "network"
            net_groups[current_group] = []
            collecting = True
        elif line.startswith("object-group service"):
            current_group = line.split()[2]
            group_type = "service"
            svc_groups[current_group] = []
            collecting = True
        elif collecting:
            if line == "" or line.startswith("object-group"):
                collecting = False
                continue
            parts = line.split()
            if group_type == "network":
                if parts[0] == "network-object":
                    if parts[1] == "host":
                        net_groups[current_group].append(parts[2] + "/32")
                    else:
                        net_groups[current_group].append(f"{parts[1]}/{mask_to_cidr(parts[2])}")
                elif parts[0] == "group-object":
                    net_groups[current_group].append("GROUP:" + parts[1])
            elif group_type == "service":
                if parts[0] == "port-object":
                    if parts[1] == "range":
                        svc_groups[current_group].append(f"{parts[2]}-{parts[3]}")
                    else:
                        svc_groups[current_group].append(parts[1])
                elif parts[0] == "group-object":
                    svc_groups[current_group].append("GROUP:" + parts[1])
    return net_groups, svc_groups


def expand_group(name, group_dict, visited=None):
    if visited is None:
        visited = set()

    if name in visited:
        return []  # avoid infinite loop
    visited.add(name)

    entries = []
    for item in group_dict.get(name, []):
        if item.startswith("GROUP:"):
            sub_group = item[6:]
            entries.extend(expand_group(sub_group, group_dict, visited))
        else:
            entries.append(item)
    return entries


def parse_acl_line(line, net_groups, svc_groups):
    tokens = line.strip().split()
    acl_name = tokens[1]

    try:
        action_index = tokens.index("extended") + 1
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
                return name, expand_group(name, net_groups)
            elif kind == "object":
                name = tokens[current + 1]
                current += 2
                return name, [name]  # optionally resolve actual object IPs here
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
            elif tokens[current] == "object-group":
                svc_name = tokens[current + 1]
                service = svc_name
                service_details = expand_group(svc_name, svc_groups)
            elif tokens[current] == "object":
                service = tokens[current +
