#!/usr/bin/env python3
"""
PHP
Tree-sitterPHP
"""

import re
from typing import List, Tuple
import os
import sys
from core.slice_diff_all.ast_parser import ASTParser
from core.slice_diff_all.common import Language
from tree_sitter import Language, Parser

class PHPCodeOneLiner:
    def __init__(self):
        """
        PHP
        PHP
        """
        try:
            self.LANGUAGE = Language("./core/slice_diff_all/build/my-languages.so", "php")
            php_parser = Parser()
            php_parser.set_language(self.LANGUAGE)
            self.parser = php_parser
            self.tree_sitter_available = True
        except:
            print("Tree-sitter PHP")
            self.tree_sitter_available = False
    
    def process_with_tree_sitter(self, code: str) -> str:
        """Tree-sitter"""
        if not self.tree_sitter_available:
            return self.process_with_regex(code)
        
        tree = self.parser.parse(bytes(code, 'utf8'))
        
        # 
        nodes_to_process = []
        self._find_multiline_nodes(tree.root_node, nodes_to_process)
        
        # 
        nodes_to_process.sort(key=lambda x: x.start_byte, reverse=True)
        
        code_bytes = code.encode('utf8')
        
        for node in nodes_to_process:
            original_text = code_bytes[node.start_byte:node.end_byte].decode('utf8')
            oneline_text = self._make_oneline(original_text)
            
            code_bytes = (code_bytes[:node.start_byte] + 
                         oneline_text.encode('utf8') + 
                         code_bytes[node.end_byte:])
        
        return code_bytes.decode('utf8')
    
    def _find_multiline_nodes(self, node, nodes_to_process):
        """"""
        # 
        if node.start_point[0] != node.end_point[0]:  # 
            # 
            if node.type in [
                'string_literal', 
                'array_creation_expression',
                'function_call_expression',
                'assignment_expression',
                'concatenation_expression'
            ]:
                nodes_to_process.append(node)
                return  # 
        
        # 
        for child in node.children:
            self._find_multiline_nodes(child, nodes_to_process)
    
    def process_with_regex(self, code: str) -> str:
        """"""
        lines = code.split('\n')
        result_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # 
            if self._is_multiline_start(line):
                # 
                multiline_content = [line]
                i += 1
                
                while i < len(lines):
                    multiline_content.append(lines[i])
                    if self._is_multiline_end(lines[i], line):
                        break
                    i += 1
                
                # 
                combined = self._combine_lines(multiline_content)
                result_lines.append(combined)
            else:
                result_lines.append(line)
            
            i += 1
        
        return '\n'.join(result_lines)
    
    def _is_multiline_start(self, line: str) -> bool:
        """"""
        stripped = line.strip()
        
        # 
        patterns = [
            r'\$\w+\s*\[\s*\]\s*=\s*[\'"]',  # 
            r'\$\w+\s*=\s*[\'"]',            # 
            r'\w+\s*\(',                      # 
            r'=\s*[\'"]',                     # 
        ]
        
        for pattern in patterns:
            if re.search(pattern, stripped) and not self._is_complete_statement(stripped):
                return True
        
        return False
    
    def _is_multiline_end(self, line: str, start_line: str) -> bool:
        """"""
        stripped = line.strip()
        
        # 
        if (stripped.endswith(';') or 
            stripped.endswith(');') or 
            stripped.endswith("';") or 
            stripped.endswith('";')):
            return True
        
        return False
    
    def _is_complete_statement(self, line: str) -> bool:
        """"""
        stripped = line.strip()
        return (stripped.endswith(';') or 
                stripped.endswith(');') or 
                stripped.endswith("';") or 
                stripped.endswith('";'))
    
    def _combine_lines(self, lines: List[str]) -> str:
        """"""
        # 
        combined = ''
        for i, line in enumerate(lines):
            stripped = line.strip()
            if i == 0:
                combined = stripped
            else:
                if stripped:
                    combined += ' ' + stripped
        
        return combined
    
    def _make_oneline(self, text: str) -> str:
        """"""
        # 
        lines = text.split('\n')
        cleaned_lines = [line.strip() for line in lines if line.strip()]
        return ' '.join(cleaned_lines)
    

# 
def main():
    # 
    code_path = "./php-cve-dataset/CVE-2023-2338/postpatch/code/AssetController.php"
    sample_code = open(code_path, 'r', encoding='utf-8').read()

    processor = PHPCodeOneLiner()
    result = processor.process_with_tree_sitter(sample_code)
    
    with open('output.php', 'w') as f:
        f.write(result)
    

if __name__ == "__main__":
    main()