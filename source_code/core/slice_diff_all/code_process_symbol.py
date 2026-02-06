import re
import os
import networkx as nx
import subprocess
cpg_dir = "./php-cve-dataset/CVE-2023-2338/prepatch/cpg"


def parse_key_value_pairs(text):
    # 
    match = re.search(r'\[(.*)\]', text)
    if not match:
        return {}
    
    content = match.group(1)
    bracket_start = match.start(1)  # 
    pairs = {}
    
    # ++
    # 
    #  label
    key_pattern = r'(?:^|\s)([A-Z_][A-Z0-9_]*)\s*='
    key_matches = list(re.finditer(key_pattern, content))
    
    if not key_matches:
        return {}
    
    for i, key_match in enumerate(key_matches):
        key = key_match.group(1)
        eq_pos = key_match.end()  # 
        
        # 
        val_start = eq_pos
        while val_start < len(content) and content[val_start] == ' ':
            val_start += 1
        
        # 
        if i < len(key_matches) - 1:  # 
            # 
            next_match_start = key_matches[i + 1].start()
            val_end = next_match_start
        else:  # 
            val_end = len(content)
        
        # 
        global_val_start = bracket_start + val_start
        global_val_end = bracket_start + val_end
        
        value = content[val_start:val_end].rstrip()  # 
        
        # 
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        
        pairs[key] = (value, (global_val_start, global_val_end))
    
    return pairs


def process(cpg_dir, key, index):
    # 
    dot_file_path = os.path.join(cpg_dir, 'fixed_export.dot')
    output_file_path = os.path.join(cpg_dir, 'fixed_export.dot')
    assert os.path.exists(dot_file_path), f"File {dot_file_path} does not exist."

    # 
    with open(dot_file_path, 'r') as file:
        lines = file.readlines()

    fixed_lines = []
    for line in lines:
        elements = parse_key_value_pairs(line)
        if key in elements:
            value, (start_index, end_index) = elements[key]
            quote_count = value.count('"')

            if quote_count > 0:
                # fixed_value = value.replace('"', r'\"')
                fixed_value = re.sub(r'(?<!\\)"', r'\"', value)
                if '\\\\"' in fixed_value:
                    print(fixed_value)
                    fixed_value = fixed_value.replace('\\\\', '\\\\\\')
                fixed_line = line[:(start_index+1)] + fixed_value + line[(end_index-1):]
                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)
        else:
            fixed_lines.append(line)
        # if 'CODE' in elements:
        #     code_value = elements['CODE'][0]
        #     start_index, end_index = elements['CODE'][1]
        #     quote_count = code_value.count('"')

        #     if quote_count > 0:
        #         fixed_code_value = code_value.replace('"', r'\"')
        #         fixed_line = line[:(start_index+1)] + fixed_code_value + line[(end_index-1):]
        #         fixed_lines.append(fixed_line)
        #     else:
        #         fixed_lines.append(line)


    #  .dot 
    with open(output_file_path, 'w') as file:
        file.writelines(fixed_lines)

    print("=" * 50)
    print(f"Processed key: {key}, Round: {index}")
    print("Fix completed! The new file is saved as 'fixed_export.dot'.")

    try:
        cpg = nx.nx_agraph.read_dot(output_file_path)
        print("Successfully read the fixed .dot file.")
    except Exception as e:
        print(f"Error reading the fixed .dot file: {e}")
        print("Continue to process the next key...")
    print("\n\n")


def dot_read_test(cpg_dir):
    try:
        cpg = nx.nx_agraph.read_dot(os.path.join(cpg_dir, 'export.dot'))
        print(f"Successfully read the fixed .dot file. [{cpg_dir}]")
        return True
    except Exception as e:
        print(f"Error reading the fixed .dot file: {e}")
        return False


def dot_preprocess(cpg_dir):
    if dot_read_test(cpg_dir):
        print("The .dot file is already fixed. No need to preprocess.")
        return
    export_cpg = os.path.join(cpg_dir, 'export.dot')
    back_cpg = os.path.join(cpg_dir, 'export_back.dot')
    fixed_cpg = os.path.join(cpg_dir, 'fixed_export.dot')
    subprocess.run(['cp', '-r', export_cpg, back_cpg])    #  .dot 
    subprocess.run(['cp', '-r', export_cpg, fixed_cpg])  #  .dot 
    
    process_key = ['CODE', 'DYNAMIC_TYPE_HINT_FULL_NAME', 'METHOD_FULL_NAME', 'NAME', 'CONTROL_STRUCTURE_TYPE', 'FULL_NAME']
    for i, key in enumerate(process_key):
        process(cpg_dir, key, i)
    subprocess.run(['cp', '-r', fixed_cpg, export_cpg])
    if dot_read_test(cpg_dir):
        print("The .dot file is fixed.")
        return


if __name__ == "__main__":
    try:
        cpg = nx.nx_agraph.read_dot(os.path.join(cpg_dir, 'export.dot'))
        print("Successfully read the fixed .dot file.")
    except Exception as e:
        print(f"Error reading the fixed .dot file: {e}")