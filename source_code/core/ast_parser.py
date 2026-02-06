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
        function/method/file
        
        
        1.  function_definition
        2.  method_declaration
        3. / body 
        4. 
        
        Args:
            slice_lines: 
            
        Returns:
            Node: 
        """
        if not slice_lines:
            return self.root
        
        # 1.  function_definition
        func_nodes = self.query_from_node(self.root, "(function_definition)@func")
        
        for func_node, _ in func_nodes:
            body = func_node.child_by_field_name("body")
            if body and self._contains_lines(body, slice_lines):
                return body
        
        # 2.  method_declaration
        method_nodes = self.query_from_node(self.root, "(method_declaration)@method")
        
        for method_node, _ in method_nodes:
            body = method_node.child_by_field_name("body")
            if body and self._contains_lines(body, slice_lines):
                return body
        
        # 3. 
        return self.root
    
    def _contains_lines(self, node, slice_lines: set) -> bool:
        """
        
        
        Args:
            node: tree-sitter 
            slice_lines: 
            
        Returns:
            bool: 
        """
        # node.start_point  end_point  (row, column) 
        # row  0  +1 
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        
        # 
        for line in slice_lines:
            if start_line <= line <= end_line:
                return True
        
        return False
    

    def get_all_functions(self) -> list[Node]:
        '''
        
        
        Returns:
            
        '''
        query_str = "(function_definition)@func (method_declaration)@method"
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_function_count(self) -> int:
        '''
        
        
        Returns:
            
        '''
        return len(self.get_all_functions())

    def get_all_classes(self) -> list[Node]:
        '''
        
        
        Returns:
            
        '''
        query_str = "(class_declaration)@class"
        captures = self.query(query_str)
        res = []
        for capture in captures:
            res.append(capture[0])
        return res

    def get_file_stats(self) -> dict:
        '''
        
        
        Returns:
            
            - function_count: 
            - class_count: 
            - method_count: 
            - standalone_function_count: 
        '''
        # 
        all_funcs = self.get_all_functions()
        
        # 
        method_query = "(method_declaration)@method"
        methods = self.query(method_query)
        method_count = len(methods)
        
        # 
        func_query = "(function_definition)@func"
        funcs = self.query(func_query)
        standalone_count = len(funcs)
        
        # 
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
        
        
        Returns:
            TrueFalse
        '''
        error_nodes = self.get_error_nodes()
        return len(error_nodes) > 0