#!/usr/bin/env python3
"""
PHP代码单行化工具
使用Tree-sitter解析PHP代码，将跨行的字符串字面量、数组声明、函数调用等合并为单行
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
        初始化PHP解析器
        注意：需要先编译PHP语言库
        """
        try:
            self.LANGUAGE = Language("./core/slice_diff_all/build/my-languages.so", "php")
            php_parser = Parser()
            php_parser.set_language(self.LANGUAGE)
            self.parser = php_parser
            self.tree_sitter_available = True
        except:
            print("Tree-sitter PHP语言库未找到，使用正则表达式方法")
            self.tree_sitter_available = False
    
    def process_with_tree_sitter(self, code: str) -> str:
        """使用Tree-sitter处理代码"""
        if not self.tree_sitter_available:
            return self.process_with_regex(code)
        
        tree = self.parser.parse(bytes(code, 'utf8'))
        
        # 获取所有需要单行化的节点
        nodes_to_process = []
        self._find_multiline_nodes(tree.root_node, nodes_to_process)
        
        # 按位置倒序排列，避免修改时位置偏移
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
        """递归查找需要单行化的多行节点"""
        # 检查是否跨行
        if node.start_point[0] != node.end_point[0]:  # 不同行
            # 检查节点类型
            if node.type in [
                'string_literal', 
                'array_creation_expression',
                'function_call_expression',
                'assignment_expression',
                'concatenation_expression'
            ]:
                nodes_to_process.append(node)
                return  # 不继续递归子节点
        
        # 递归处理子节点
        for child in node.children:
            self._find_multiline_nodes(child, nodes_to_process)
    
    def process_with_regex(self, code: str) -> str:
        """使用正则表达式处理代码（备用方案）"""
        lines = code.split('\n')
        result_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # 检查是否是多行字符串的开始
            if self._is_multiline_start(line):
                # 收集多行内容
                multiline_content = [line]
                i += 1
                
                while i < len(lines):
                    multiline_content.append(lines[i])
                    if self._is_multiline_end(lines[i], line):
                        break
                    i += 1
                
                # 合并为单行
                combined = self._combine_lines(multiline_content)
                result_lines.append(combined)
            else:
                result_lines.append(line)
            
            i += 1
        
        return '\n'.join(result_lines)
    
    def _is_multiline_start(self, line: str) -> bool:
        """判断是否是多行结构的开始"""
        stripped = line.strip()
        
        # 检查各种多行模式
        patterns = [
            r'\$\w+\s*\[\s*\]\s*=\s*[\'"]',  # 数组赋值开始
            r'\$\w+\s*=\s*[\'"]',            # 字符串赋值开始
            r'\w+\s*\(',                      # 函数调用开始
            r'=\s*[\'"]',                     # 赋值开始
        ]
        
        for pattern in patterns:
            if re.search(pattern, stripped) and not self._is_complete_statement(stripped):
                return True
        
        return False
    
    def _is_multiline_end(self, line: str, start_line: str) -> bool:
        """判断多行结构是否结束"""
        stripped = line.strip()
        
        # 检查结束标志
        if (stripped.endswith(';') or 
            stripped.endswith(');') or 
            stripped.endswith("';") or 
            stripped.endswith('";')):
            return True
        
        return False
    
    def _is_complete_statement(self, line: str) -> bool:
        """判断是否是完整的语句"""
        stripped = line.strip()
        return (stripped.endswith(';') or 
                stripped.endswith(');') or 
                stripped.endswith("';") or 
                stripped.endswith('";'))
    
    def _combine_lines(self, lines: List[str]) -> str:
        """将多行合并为单行"""
        # 移除每行的前导空白，保留一个空格连接
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
        """将文本转换为单行"""
        # 移除多余的空白字符，保留必要的空格
        lines = text.split('\n')
        cleaned_lines = [line.strip() for line in lines if line.strip()]
        return ' '.join(cleaned_lines)
    

# 示例用法
def main():
    # 你提供的示例代码
    code_path = "/home/xinchu/research/RecurScan/SanCheck/php-cve-dataset/CVE-2023-2338/postpatch/code/AssetController.php"
    sample_code = open(code_path, 'r', encoding='utf-8').read()

    processor = PHPCodeOneLiner()
    result = processor.process_with_tree_sitter(sample_code)
    
    with open('output.php', 'w') as f:
        f.write(result)
    

if __name__ == "__main__":
    main()