import sys
from typing import Generator

import tree_sitter_c as tsc
import tree_sitter_php as tsphp
from tree_sitter import Language, Node, Parser

import core.common as common

TS_PHP_NAMESPACE = "(namespace_declaration (scoped_identifier) @namespace)(namespace_declaration (identifier) @namespace)"
TS_PHP_USE = "(use_declaration (scoped_identifier) @use)"
TS_PHP_CLASS = "(class_declaration) @class"
TS_PHP_PROPERTY = "(property_declaration) @property"
TS_C_INCLUDE = "(preproc_include (system_lib_string)@string_content)(preproc_include (string_literal)@string_content)"
TS_C_METHOD = "(function_definition)@method"
TS_COND_STAT = "(if_statement)@name (while_statement)@name (for_statement)@name"
TS_ASSIGN_STAT = "(assignment_expression)@name"
TS_PHP_METHOD = "(method_declaration) @method (function_definition) @method"
TS_METHODNAME = "(method_declaration 	(identifier)@id)(constructor_declaration 	(identifier)@id)"
TS_FPARAM = "(formal_parameters)@name"


class ASTParser:
    def __init__(self, code: str | bytes, language: common.Language | int):
        if language == common.Language.C:
            self.LANGUAGE = Language(tsc.language())
        else:
            # self.LANGUAGE = Language(tsphp.language_php())
            self.LANGUAGE = Language("./core/build/my-languages.so", "php")
            php_parser = Parser()
            php_parser.set_language(self.LANGUAGE)
        self.parser = php_parser if language == common.Language.PHP else Parser()
        if isinstance(code, str):
            self.tree = self.parser.parse(bytes(code, "utf-8"))
        elif isinstance(code, bytes):
            self.tree = self.parser.parse(code)
        self.root = self.tree.root_node

    @staticmethod
    def children_by_type_name(node: Node, type: str) -> list[Node]:
        node_list = []
        for child in node.named_children:
            if child.type == type:
                node_list.append(child)
        return node_list

    @staticmethod
    def child_by_type_name(node: Node, type: str) -> Node | None:
        for child in node.named_children:
            if child.type == type:
                return child
        return None

    def traverse_tree(self) -> Generator[Node, None, None]:
        cursor = self.tree.walk()
        visited_children = False
        while True:
            if not visited_children:
                assert cursor.node is not None
                yield cursor.node
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

    def query_oneshot(self, query_str: str) -> Node | None:
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        result = None
        for capture in captures:
            result = capture[0]
            break
        return result

    def query(self, query_str: str):
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        return captures

    def query_from_node(self, node: Node, query_str: str):
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(node)
        return captures

    def get_error_nodes(self) -> list[Node]:
        query_str = """
        (ERROR)@error
        """
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_all_identifier_node(self, language) -> list[Node]:
        if language == common.Language.C:
            query_str = """
            (identifier) @id
            """
        elif language == common.Language.PHP:
            query_str = """
            (variable_name) @var
            """
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_all_conditional_node(self) -> list[Node]:
        query_str = TS_COND_STAT
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_all_assign_node(self) -> list[Node]:
        query_str = """
        (assignment_expression)@name  ( declaration )@name
        """
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_all_return_node(self) -> list[Node]:
        query_str = """
        (return_statement)@name
        """
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_all_call_node(self) -> list[Node]:
        query_str = """
        (call_expression)@name
        """
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_all_includes(self) -> list[Node]:
        if self.LANGUAGE == Language(tsc.language()):
            query_str = """
            (preproc_include)@name
            """
        else:
            query_str = """
            ( import_declaration)@name
            """
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res


    def find_containing_scope(self, slice_lines: set):
        """
        查找包含切片行的作用域（function/method/file）
        
        处理流程：
        1. 先查找所有 function_definition
        2. 如果没有找到，查找所有 method_declaration
        3. 检查哪个函数/方法的 body 包含这些行
        4. 如果都不包含，说明代码直接在文件中，返回根节点
        
        Args:
            slice_lines: 切片行号集合
            
        Returns:
            Node: 作用域节点（函数体、方法体或根节点）
        """
        if not slice_lines:
            return self.root
        
        # 1. 先查找所有 function_definition
        func_nodes = self.query_from_node(self.root, "(function_definition)@func")
        
        for func_node, _ in func_nodes:
            body = func_node.child_by_field_name("body")
            if body and self._contains_lines(body, slice_lines):
                return body
        
        # 2. 如果没找到，查找所有 method_declaration
        method_nodes = self.query_from_node(self.root, "(method_declaration)@method")
        
        for method_node, _ in method_nodes:
            body = method_node.child_by_field_name("body")
            if body and self._contains_lines(body, slice_lines):
                return body
        
        # 3. 都没找到，代码直接在文件中
        return self.root
    
    def _contains_lines(self, node, slice_lines: set) -> bool:
        """
        检查节点是否包含切片行
        
        Args:
            node: tree-sitter 节点
            slice_lines: 切片行号集合
            
        Returns:
            bool: 是否包含任意切片行
        """
        # node.start_point 和 end_point 是 (row, column) 元组
        # row 是从 0 开始的，所以需要 +1 转换为实际行号
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        
        # 检查是否有任何切片行在这个范围内
        for line in slice_lines:
            if start_line <= line <= end_line:
                return True
        
        return False
    

    def get_all_functions(self) -> list[Node]:
        '''
        获取所有函数定义（包括普通函数和类方法）
        
        Returns:
            函数节点列表
        '''
        query_str = "(function_definition)@func (method_declaration)@method"
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_function_count(self) -> int:
        '''
        获取函数总数（包括普通函数和类方法）
        
        Returns:
            函数数量
        '''
        return len(self.get_all_functions())

    def get_all_classes(self) -> list[Node]:
        '''
        获取所有类定义
        
        Returns:
            类节点列表
        '''
        query_str = "(class_declaration)@class"
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_file_stats(self) -> dict:
        '''
        获取文件的统计信息
        
        Returns:
            包含以下信息的字典：
            - function_count: 函数数量
            - class_count: 类数量
            - method_count: 方法数量（仅类方法）
            - standalone_function_count: 独立函数数量（不在类中的函数）
        '''
        # 所有函数（包括方法）
        all_funcs = self.get_all_functions()
        
        # 仅方法
        method_query = "(method_declaration)@method"
        methods = self.query(method_query)
        method_count = len(methods)
        
        # 仅独立函数
        func_query = "(function_definition)@func"
        funcs = self.query(func_query)
        standalone_count = len(funcs)
        
        # 类数量
        classes = self.get_all_classes()
        class_count = len(classes)
        
        return {
            'function_count': len(all_funcs),
            'class_count': class_count,
            'method_count': method_count,
            'standalone_function_count': standalone_count
        }

    def has_syntax_errors(self) -> bool:
        '''
        检查是否有语法错误
        
        Returns:
            如果有语法错误返回True，否则返回False
        '''
        error_nodes = self.get_error_nodes()
        return len(error_nodes) > 0