import re
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment

object_groups = {}
service_groups = {}

def parse_object_groups(lines):
    current_group = ""
    is_service = False

    for line in lines:
        line = line.strip()
        if line.startswith("object-group network "):
            current_group = line.split()[2]
            is_service = False
            object_groups[current_group] = []
        elif line.startswith("object-group service "):
            current_group = line.split()[2]
            is_service = True
            service_groups[current_group] = []
        elif line.startswith("group-object "):
            group_name = line.split()[1]
            target = service_groups if is_service else object_groups
            target[current_group].append(f"group:{group_name}")
        elif line.startswith("network-object") or line.startswith("service-object"):
            item = " ".join(line.split()[1:])
            target = service_groups if is_service else object_groups
            target[current_group].append(item)

def resolve_group(name, is_service=False):
    result = []
    visited = set()
    stack = [name]
    groups = service_groups if is_service else object_groups

    while stack:
        group = stack.pop()
        if group in visited:
            continue
        visited.add(group)
        for item in groups.get(group, []):
            if item.startswith("group:"):
                stack.append(item.split(":", 1)[1])
            else:
                result.append(item)
    return result

def resolve_token(token, is_service=False):
    if token == "any":
        return ["any"]
    elif token.startswith("object-group") or token.startswith("object"):
        name = token.split()[-1]
        return resolve_group(name, is_service)
    else:
        return [token]

def get_group_name(token):
    if token.startswith("object-group") or token.startswith("object"):
        return token.split()[-1]
    return ""

def parse_access_lists(lines):
    data = []
    for line in lines:
        if not line.startswith("access-list"):
            continue

        parts = re.split(r"\s+", line)
        if len(parts) < 11:
            continue

        acl_name = parts[1]
        service = parts[6]
        source = parts[8]
        destination = parts[10]

        src_group = get_group_name(source)
        dst_group = get_group_name(destination)
        srv_group = get_group_name(service)

        src_contents = "\n".join(resolve_group(src_group, False)) if src_group else ""
        dst_contents = "\n".join(resolve_group(dst_group, False)) if dst_group else ""
        srv_contents = "\n".join(resolve_group(srv_group, True)) if srv_group else ""

        for s in resolve_token(source, False):
            for d in resolve_token(destination, False):
                for srv in resolve_token(service, True):
                    data.append([
                        acl_name, s, d, srv,
                        src_group, src_contents,
                        dst_group, dst_contents,
                        srv_group, srv_contents
                    ])
    return data

def write_to_excel(data, output_path):
    wb = Workbook()
    ws = wb.active
    ws.title = "AccessLists"

    headers = [
        "access-list", "source", "destination", "service",
        "source-group-name", "source-group-contents",
        "destination-group-name", "destination-group-contents",
        "service-group-name", "service-group-contents"
    ]

    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)

    for row in data:
        ws.append(row)

    # Wrap text for group contents
    for row in ws.iter_rows(min_row=2, min_col=6, max_col=10):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True)

    for column_cells in ws.columns:
        max_length = max(len(str(cell.value) if cell.value else "") for cell in column_cells)
        ws.column_dimensions[column_cells[0].column_letter].width = max_length + 2

    wb.save(output_path)
    print(f"Saved Excel file to {output_path}")

def main():
    config_path = "asa_config.txt"
    output_path = "access_list_output.xlsx"

    with open(config_path, "r") as file:
        lines = file.readlines()

    parse_object_groups(lines)
    access_data = parse_access_lists(lines)
    write_to_excel(access_data, output_path)

if __name__ == "__main__":
    main()