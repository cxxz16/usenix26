import os
import sys
sys.path.append("")
from ground_truth.slice_diff_all.ast_parser import ASTParser
from ground_truth.slice_diff_all.common import Language

def vuln_code_extract(code_path, func_name, outfile):
    code = open(code_path, "r", encoding="utf-8").read()
    ast = ASTParser(code, Language.PHP)
    root_node = ast.root
    
    def find_function_with_path(node, path=[]):
        # 
        if node.type in ['function_definition', 'method_declaration']:
            for child in node.children:
                if child.type == 'name' and child.text.decode('utf-8') == func_name:
                    return node, path
        
        # 
        for child in node.children:
            result = find_function_with_path(child, path + [node])
            if result[0]:
                return result
        return None, []
    
    func_node, node_path = find_function_with_path(root_node)
    
    if func_node:
        # class_declaration
        class_node = None
        for node in reversed(node_path):
            if node.type == 'class_declaration':
                class_node = node
                break
        
        if class_node:
            # class
            class_start = class_node.start_byte
            class_body_start = None
            for child in class_node.children:
                if child.type == 'declaration_list':
                    class_body_start = child.start_byte
                    break
            
            class_declaration = code[class_start:class_body_start].strip()
            func_code = code[func_node.start_byte:func_node.end_byte]
            
            php_content = f"<?php\n\n{class_declaration}\n{{\n\n{func_code}\n\n}}\n\n?>"
        else:
            func_code = code[func_node.start_byte:func_node.end_byte]
            php_content = f"<?php\n\n{func_code}\n\n?>"
        
        with open(outfile, 'w', encoding='utf-8') as f:
            f.write(php_content)
        
        return True
    
    return False


if __name__ == "__main__":
    code_path = "./php-cve-dataset/CVE-2023-2338/prepatch/code/AssetController.php"
    vuln_code_extract(code_path, "downloadAsZipAddFilesAction", "vuln_code.php")