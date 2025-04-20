# asa_acl_parser
Scripts to pull in asa running_config and output a .xlsx file with the contents of the configured access list broken down into its elements.

===============================================
----------------‐
asa_parser.py
----------------

Python script using openpyxl to output an .xlsx file with support for:

Parsing access-list lines

Resolving nested object-group and service-group references

Inserting multiple entries into the same Excel cell using line breaks

Auto-fitting column widths and enabling wrap text


---

✅ Dependencies

Install openpyxl if you haven’t:

pip install openpyxl

---

Example Usage:

1. Save your ASA config in asa_config.txt
2. Run the script:

bash
python asa_parser.py

3. It will generate: access_list_output.xlsx

==================================================

