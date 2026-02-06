from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
import sys
from tree_sitter import Node
sys.path.append("./SanCheck/")
from ground_truth.slice_diff_all.common import Language
from ground_truth.slice_diff_all.ast_parser import ASTParser

class InterproceduralForwardSlicer:
    def __init__(self, analyzer: Neo4jEngine, direction=None):
        """
        
        
        Args:
            analyzer:  PDG 
        """
        self.analyzer = analyzer
        self.visited_nodes = set()
        self.slice_result = []
        self.language = Language.PHP
        # direction  source  patch  patch  sink
        self.direction = direction
        
    def forward_slice(self, call_path, patch_statements=[]):
        """
        
        
        Args:
            start_node_id: ID
            call_path: 
            
        Returns:
            list: ID
        """
        self.visited_nodes.clear()
        self.slice_result.clear()
        
        if not call_path:
            return self.slice_result
        
        #  patch 
        start_node_id = []
        backward_nodes = []
        for patch_stmt in patch_statements:
            start_node_id.append(patch_stmt['call_site_nodeid'])

        # : 
        if start_node_id:
            backward_nodes = self._backward_slice_initial(start_node_id)

        # : 
        for node_id in backward_nodes:
            #  patch statement  backward slice 
            self._slice_in_function(node_id)

        # 
        if self.direction == None:    #  patch  sink
            call_path.insert(0, patch_statements[0])  #  patch statement 
            self._forward_slice_from_node(node_id, call_path, 0)
        elif self.direction == "sp":
            if patch_statements:
                call_path.append(patch_statements[0])  #  patch statement 
            self._forward_slice_from_node(call_path[0]['call_site_nodeid'], call_path, 0)

        return list(set(self.slice_result))  # 
    
    
    def forward_slice_intra(self, patch_statements=[]):
        """
        +
        
        Args:
            start_node_id: ID
            
        Returns:
            list: ID
        """
        self.visited_nodes.clear()
        self.slice_result.clear()

        #  patch 
        start_node_id = []
        backward_nodes = []
        for patch_stmt in patch_statements:
            start_node_id.append(patch_stmt['call_site_nodeid'])

        # : 
        if start_node_id:
            backward_nodes = self._backward_slice_initial(start_node_id)

        # : 
        for node_id in backward_nodes:
            #  patch statement  backward slice 
            self._slice_in_function(node_id, patch_statements[-1]['call_site_nodeid'])

        return list(set(self.slice_result))  # 


    def forward_slice_source_patch(self, call_path, patch_statements=[]):
        """
        
        
        Args:
            start_node_id: ID
            call_path: 
            
        Returns:
            list: ID
        """
        self.visited_nodes.clear()
        self.slice_result.clear()
        
        if not call_path:
            return self.slice_result
    
        if self.direction == "sp":
            # if patch_statements:
            #     call_path.append(patch_statements[0])  #  patch statement 
            self._forward_slice_from_node_source_patch(call_path[0]['call_site_nodeid'], call_path, 0)


        #  patch statement 
        start_node_id = []
        backward_nodes = []
        for patch_stmt in patch_statements:
            start_node_id.append(patch_stmt['call_site_nodeid'])

        # : 
        if start_node_id:
            backward_nodes = self._backward_slice_initial(start_node_id)

        # : 
        for node_id in backward_nodes:
            #  patch statement  backward slice 
            self._slice_in_function(node_id)

        return list(set(self.slice_result))  # 
    

    def forward_slice_source_sink(self, call_path):
        """
        source  sink 
        
        Args:
            start_node_id: ID
            call_path: 
            
        Returns:
            list: ID
        """
        self.visited_nodes.clear()
        self.slice_result.clear()
        
        if not call_path:
            return self.slice_result
    
        if self.direction == "sp":
            # if patch_statements:
            #     call_path.append(patch_statements[0])  #  patch statement 
            self._forward_slice_from_node_source_patch(call_path[0]['call_site_nodeid'], call_path, 0)

        #  source  check condition 
        # self._slice_in_function(call_path[0]['call_site_nodeid'] - 300, call_path[0]['call_site_nodeid'])
        

        return list(set(self.slice_result))  # 

    
    def _backward_slice_initial(self, start_node_id):
        """
        ,
        
        Args:
            start_node_id: ID
            first_path_item: ,
            
        Returns:
            list: ID
        """
        backward_result = []
        visited = set()
        worklist = start_node_id

        while worklist:
            current_id = worklist.pop(0)
            
            if current_id in visited:
                continue
                
            visited.add(current_id)
            backward_result.append(current_id)
            
            # 
            current_node = self.analyzer.get_node_itself(current_id)
            if not current_node:
                continue
            
            #  PDG  def ()
            ast_root = self.analyzer.get_ast_root_node(current_node)
            def_nodes = self.analyzer.pdg_step.find_def_nodes(ast_root)
            
            for def_node in def_nodes:
                def_id = def_node[NODE_INDEX]
                if def_id and def_id not in visited:
                    worklist.append(def_id)
        
        return backward_result
    

    def _forward_slice_from_node(self, start_node_id, call_path, path_index):
        """
        ,
        
        Args:
            start_node_id: ID
            call_path: 
            path_index: 
        """
        current_node_id = start_node_id
        
        while path_index < len(call_path):
            current_path = call_path[path_index]
            
            # ,
            if path_index + 1 < len(call_path):
                next_path = call_path[path_index + 1]
                
                if 'caller_name' in next_path:
                    #  caller: 
                    function_name = current_path.get('caller_name', '')
                    # 
                    current_node_id = next_path['call_site_nodeid']
                    if next_path['level'] == current_path:
                        self._slice_in_function(current_node_id, current_node_id)
                    self._slice_in_function(current_node_id)
                    # :  caller 
                    
                elif 'callee_name' in next_path:
                    #  callee:  callsite
                    callsite_node_id = next_path['call_site_nodeid']
                    function_name = current_path.get('callee_name', '')
                    self._slice_to_target(current_node_id, callsite_node_id, function_name)
                    
                    # :  callee 
                    callee_name = next_path['callee_name']
                    param_pos = next_path.get('param_pos', 0)

                    callsite_node = self.analyzer.get_node_itself(callsite_node_id)
                    param_node_id = self._get_function_param_node(callsite_node, param_pos)
                
                    if param_node_id:
                        current_node_id = param_node_id
                    else:
                        # ,
                        return
                
            else:
                # 
                if 'caller_name' in current_path:
                    #  caller: 
                    return_node_id = current_path['call_site_nodeid']
                    function_name = current_path.get('caller_name', '')
                    self._slice_to_target(current_node_id, return_node_id, function_name)
                
                elif 'callee_name' in current_path:
                    #   callsite caller  callsitecallee callsite 
                    pass

                    #  callee: 
                    # callee_name = current_path['callee_name']
                    # param_pos = current_path.get('param_pos', 0)
                    
                    # callsite_node = self.analyzer.get_node_itself(current_path['call_site_nodeid'])
                    # param_node_id = self._get_function_param_node(callsite_node, param_pos)

                    # if param_node_id:
                    #     #  callee 
                    #     self._slice_in_function(param_node_id, None)
            path_index += 1



    def _forward_slice_from_node_source_patch(self, start_node_id, call_path, path_index):
        """
        ,
        
        Args:
            start_node_id: ID
            call_path: 
            path_index: 
        """
        current_node_id = start_node_id
        
        while path_index < len(call_path):
            current_path = call_path[path_index]
            
            # ,
            if path_index + 1 < len(call_path):
                next_path = call_path[path_index + 1]
                
                if 'caller_name' in next_path:
                    #  caller: 
                    function_name = current_path.get('caller_name', '')
                    # 
                    callersite_node_id = next_path['call_site_nodeid']

                    #  current_node_id  backword initial node set
                    cur_backward_nodes = self._backward_slice_initial([current_node_id])

                    if next_path.get('level', -1) == current_path.get('level', -1):
                        self._slice_in_function(cur_backward_nodes, callersite_node_id)
                    else:
                        self._slice_in_function(cur_backward_nodes)
                    # :  caller 
                    current_node_id = callersite_node_id
                    
                elif 'callee_name' in next_path:
                    #  callee:  callsite
                    callsite_node_id = next_path['call_site_nodeid']
                    function_name = current_path.get('callee_name', '')
                    if current_node_id != current_path["call_site_nodeid"]:
                        cur_backward_nodes = self._backward_slice_initial([current_node_id, current_path["call_site_nodeid"]])
                    else:
                        cur_backward_nodes = self._backward_slice_initial([current_node_id])
                    cur_backward_nodes = self._backward_slice_initial([current_node_id])
                    self._slice_to_target(cur_backward_nodes, callsite_node_id, function_name)
                    
                    # :  callee 
                    callee_name = next_path['callee_name']
                    param_pos = next_path.get('param_pos', 0)

                    callsite_node = self.analyzer.get_node_itself(callsite_node_id)
                    if param_pos != -1:
                        param_node_id = self._get_function_param_node(callsite_node, param_pos)
                
                        if param_node_id:
                            current_node_id = param_node_id
                        else:
                            print(f"Cannot find parameter node for function: {callee_name}, param_pos: {param_pos}")
                    else:
                        # ,
                        # TODO: sink  param +
                        path_index += 1
                        continue
                
            else:
                # 
                if 'caller_name' in current_path:
                    #  caller: 
                    return_node_id = current_path['call_site_nodeid']
                    function_name = current_path.get('caller_name', '')
                    cur_backward_nodes = self._backward_slice_initial([current_node_id])
                    
                    self._slice_to_target(cur_backward_nodes, return_node_id, function_name)
                
                elif 'callee_name' in current_path:
                    #   callsite caller  callsitecallee callsite 
                    # pass
                    try:
                        if current_node_id != current_path["call_site_nodeid"]:
                            cur_backward_nodes = self._backward_slice_initial([current_node_id, current_path["call_site_nodeid"]])
                        else:
                            cur_backward_nodes = self._backward_slice_initial([current_node_id])
                        self._slice_in_function(cur_backward_nodes, current_node_id)
                    except Exception as e:
                        print(f"Error in last callee slicing: {e}")
                    finally:
                        pass

                    #  callee: 
                    # callee_name = current_path['callee_name']
                    # param_pos = current_path.get('param_pos', 0)
                    
                    # callsite_node = self.analyzer.get_node_itself(current_path['call_site_nodeid'])
                    # param_node_id = self._get_function_param_node(callsite_node, param_pos)

                    # if param_node_id:
                    #     #  callee 
                    #     self._slice_in_function(param_node_id, None)
            path_index += 1

    
    def _slice_to_target(self, start_node_id, target_node_id, function_name):
        """
        
        
        Args:
            start_node_id: ID
            target_node_id: IDcallsite
            function_name: 
        """
        if type(start_node_id) == list:
            worklist = start_node_id
        else:
            worklist = [start_node_id]
        # worklist = [start_node_id]
        
        while worklist:
            current_id = worklist.pop(0)
            
            if current_id in self.visited_nodes:
                continue
                
            self.visited_nodes.add(current_id)
            self.slice_result.append(current_id)
            
            # 
            if current_id >= target_node_id:
                continue
            
            # 
            current_node = self.analyzer.get_node_itself(current_id)
            if not current_node:
                continue
            
            #  PDG  use 
            ast_root = self.analyzer.get_ast_root_node(current_node)
            reach_to_nodes = self.analyzer.pdg_step.find_use_nodes(ast_root)
            
            for next_node in reach_to_nodes:
                next_id = next_node[NODE_INDEX]
                if next_id and next_id not in self.visited_nodes:
                    # 
                    if next_id <= target_node_id:
                        worklist.append(next_id)
    
    def _slice_in_function(self, start_node_id, end_node_id=None):
        """
        end_node_id
        
        Args:
            start_node_id: ID
            function_name: 
            end_node_id: ID
        """
        if type(start_node_id) == list:
            worklist = start_node_id
        else:
            worklist = [start_node_id]
        
        while worklist:
            current_id = worklist.pop(0)
            
            if current_id in self.visited_nodes:
                continue
                
            self.visited_nodes.add(current_id)
            self.slice_result.append(current_id)
            
            # 
            if end_node_id and current_id >= end_node_id:
                continue
            
            # 
            current_node = self.analyzer.get_node_itself(current_id)
            if not current_node:
                continue
            
            #  PDG  use 
            ast_root = self.analyzer.get_ast_root_node(current_node)
            reach_to_nodes = self.analyzer.pdg_step.find_use_nodes(ast_root)
            
            for next_node in reach_to_nodes:
                next_id = next_node[NODE_INDEX]
                if next_id and next_id not in self.visited_nodes:
                    # if self._is_in_same_function(next_id, function_name):
                    if end_node_id is None or next_id <= end_node_id:
                        worklist.append(next_id)

    def _get_function_param_node(self, callsite_node, param_pos):
        """
        ID
        
        Args:
            function_name: 
            param_pos: 0-based
            
        Returns:
            int: ID
        """
        # return self.analyzer.get_function_param_node_id(function_name, param_pos)
        func_decls = self.analyzer.cg_step.find_decl_nodes(callsite_node)
        if func_decls:
            func_decl = func_decls[0]
            params_node = self.analyzer.ast_step.find_function_param_node_list(func_decl)
            if params_node and param_pos < len(params_node):
                param_node = params_node[param_pos]
                return param_node[NODE_INDEX]
        return None
    

    def nodes_to_code(self, node_ids):
        """
        ID
        
        Args:
            node_ids: ID
            
        Returns:
            dict:  {file_path: [(line_no, code, original_index), ...]}
        """
        # 
        file_lines = {}  # {file_path: [(line_no, node_id, original_index), ...]}
        
        for idx, node_id in enumerate(node_ids):
            node = self.analyzer.get_node_itself(node_id)
            if node is None:
                continue
            
            # 
            line_no = node.get('lineno')
            if line_no is None:
                continue
            
            # 
            file_path = self.analyzer.fig_step.get_belong_file(node)
            if file_path is None:
                continue
            
            if file_path not in file_lines:
                file_lines[file_path] = []
            
            file_lines[file_path].append((line_no, node_id, idx))
        
        # 
        result = {}
        for file_path, lines_list in file_lines.items():
            # 
            slice_lines = set([line_no for line_no, _, _ in lines_list])
            
            # 
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue
            
            #  tree-sitter 
            fixed_lines = self._fix_code_with_treesitter(file_content, slice_lines, file_path)
            
            # 
            file_lines_list = file_content.split('\n')
            result[file_path] = []
            
            # 
            for scope_name, lines_in_scope in fixed_lines.items():
                scope_code = [file_lines_list[l - 1] for l in sorted(lines_in_scope)]
                result[file_path].append((scope_name, scope_code))

        return result

    def _fix_code_with_treesitter(self, code, slice_lines, file_path):
        """
         tree-sitter 
        
        Args:
            code: 
            slice_lines: 
            file_path: 
            
        Returns:
            set: 
        """

        #  AST
        ast = ASTParser(code, self.language)
        
        # /
        scope_mapping = self.map_lines_to_scopes(ast, slice_lines)
        
        # 
        all_fixed_lines: dict[str, set[int]] = {}
        
        for scope_info, lines_in_scope in scope_mapping.items():
            scope_type, scope_name, body_node = scope_info
            
            # 
            fixed_lines = lines_in_scope.copy()
            # fixed_lines = self._trim_if_statements(ast, body_node, fixed_lines)
            # fixed_lines = self._trim_loops(ast, body_node, fixed_lines)
            # fixed_lines = self._trim_switch_statements(ast, body_node, fixed_lines)
            # fixed_lines = self._trim_try_catch(ast, body_node, fixed_lines)
            # fixed_lines = self._trim_blocks(ast, body_node, fixed_lines)

            self.ast_dive_php(body_node, fixed_lines)
            
            all_fixed_lines[scope_name] = fixed_lines
        
        return all_fixed_lines
    
    def _trim_if_statements(self, ast_parser, root, slice_lines):
        """
         if  if  body  if 
        """
        #  if 
        if_nodes = ast_parser.query_from_node(root, "(if_statement)@if")
        if_nodes = [node[0] for node in if_nodes if node[0].type == "if_statement"]
        
        for if_node in if_nodes:
            #  else if  if
            if if_node.parent is not None and if_node.parent.type == "else_clause":
                continue
            
            condition_node = if_node.child_by_field_name("condition")
            consequence_node = if_node.child_by_field_name("body")
            
            if condition_node is None or consequence_node is None:
                continue
            
            # 
            if_node_lines = set(range(if_node.start_point[0] + 1, if_node.end_point[0] + 2))
            condition_lines = set(range(condition_node.start_point[0] + 1, condition_node.end_point[0] + 2))
            consequence_lines = set(range(consequence_node.start_point[0] + 1, consequence_node.end_point[0] + 1))
            
            #  consequence  { 
            if consequence_node.text is not None and consequence_node.text.decode().startswith("{\n"):
                consequence_lines -= {consequence_node.start_point[0] + 1}
            
            #  consequence  if 
            if len(consequence_lines.intersection(slice_lines)) == 0:
                slice_lines -= if_node_lines
        
        return slice_lines
    
    def _trim_loops(self, ast_parser, root, slice_lines):
        """
        for, while, foreach, do-while
        """
        # 
        loop_queries = [
            "(for_statement)@loop",
            "(while_statement)@loop",
            "(foreach_statement)@loop",
            "(do_statement)@loop"
        ]
        
        for query in loop_queries:
            loop_nodes = ast_parser.query_from_node(root, query)
            loop_nodes = [node[0] for node in loop_nodes]
            
            for loop_node in loop_nodes:
                body_node = loop_node.child_by_field_name("body")
                if body_node is None:
                    #  body 
                    for child in loop_node.children:
                        if child.type == "compound_statement":
                            body_node = child
                            break
                
                if body_node is None:
                    continue
                
                #  body 
                body_lines = set(range(body_node.start_point[0] + 1, body_node.end_point[0] + 1))
                
                #  body  { 
                if body_node.text is not None and body_node.text.decode().startswith("{\n"):
                    body_lines -= {body_node.start_point[0] + 1}
                
                #  body 
                if len(body_lines.intersection(slice_lines)) == 0:
                    loop_lines = set(range(loop_node.start_point[0] + 1, loop_node.end_point[0] + 2))
                    slice_lines -= loop_lines
        
        return slice_lines
    
    def _trim_switch_statements(self, ast_parser, root, slice_lines):
        """
         switch  case 
        """
        switch_nodes = ast_parser.query_from_node(root, "(switch_statement)@switch")
        switch_nodes = [node[0] for node in switch_nodes if node[0].type == "switch_statement"]
        
        for switch_node in switch_nodes:
            #  case  default
            case_nodes = []
            for child in switch_node.children:
                if child.type in ["case_statement", "default_statement"]:
                    case_nodes.append(child)
            
            for case_node in case_nodes:
                #  case 
                case_lines = set(range(case_node.start_point[0] + 1, case_node.end_point[0] + 2))
                
                #  case 
                case_label_line = case_node.start_point[0] + 1
                
                #  case body 
                case_body_lines = case_lines - {case_label_line}
                
                #  case body  case
                if len(case_body_lines.intersection(slice_lines)) == 0:
                    slice_lines -= case_lines
        
        return slice_lines
    
    def _trim_try_catch(self, ast_parser, root, slice_lines):
        """
         try-catch 
        """
        try_nodes = ast_parser.query_from_node(root, "(try_statement)@try")
        try_nodes = [node[0] for node in try_nodes if node[0].type == "try_statement"]
        
        for try_node in try_nodes:
            body_node = try_node.child_by_field_name("body")
            if body_node is None:
                continue
            
            #  try body 
            body_lines = set(range(body_node.start_point[0] + 1, body_node.end_point[0] + 1))
            
            #  try body  try 
            if len(body_lines.intersection(slice_lines)) == 0:
                try_lines = set(range(try_node.start_point[0] + 1, try_node.end_point[0] + 2))
                slice_lines -= try_lines
            else:
                #  catch 
                catch_nodes = [child for child in try_node.children if child.type == "catch_clause"]
                for catch_node in catch_nodes:
                    catch_body = catch_node.child_by_field_name("body")
                    if catch_body is None:
                        continue
                    
                    catch_body_lines = set(range(catch_body.start_point[0] + 1, catch_body.end_point[0] + 1))
                    
                    #  catch body  catch
                    if len(catch_body_lines.intersection(slice_lines)) == 0:
                        catch_lines = set(range(catch_node.start_point[0] + 1, catch_node.end_point[0] + 2))
                        slice_lines -= catch_lines
        
        return slice_lines
    
    def _trim_blocks(self, ast_parser, root, slice_lines):
        """
         compound_statement 
        """
        block_nodes = ast_parser.query_from_node(root, "(compound_statement)@block")
        block_nodes = [node[0] for node in block_nodes if node[0].type == "compound_statement"]
        
        for block_node in block_nodes:
            # 
            block_lines = set(range(block_node.start_point[0] + 1, block_node.end_point[0] + 2))
            
            # 
            block_start = block_node.start_point[0] + 1
            block_end = block_node.end_point[0] + 1
            block_content_lines = block_lines - {block_start, block_end}
            
            # 
            if len(block_content_lines.intersection(slice_lines)) == 0:
                # 
                if block_node.parent and block_node.parent.type not in ["function_definition", "method_declaration"]:
                    slice_lines -= block_lines
        
        return slice_lines

    def extract_path(self, full_path: str) -> str:
        prefix = "./projects/"
        
        if not full_path.startswith(prefix):
            return full_path  #  return None

        rest = full_path[len(prefix):]           # 
        return rest.split("/", 1)[1]              # CVE-xxxx
    
    def export_slice_code(self, node_ids, output_file=None, call_relations=None):
        """
        
        
        Args:
            node_ids: ID
            output_file: 
            
        Returns:
            str: 
        """
        
        code_dict = self.nodes_to_code(node_ids)
        
        output_lines = []
        for file_path in sorted(code_dict.keys()):
            # output_lines.append(f"\n{'='*80}")
            output_lines.append(f"// File: {self.extract_path(file_path)}\n")
            # output_lines.append('='*80)

            for code_tuple in code_dict[file_path]:
                scope_name, scope_code = code_tuple
                if scope_name == "<global>":
                    output_lines.append(f"// Scope: Global Scope\n")
                output_lines.extend([f"{line}" for line in scope_code])
                output_lines.append("\n")  # 

        result = '\n'.join(output_lines)
        
        if call_relations is not None:
            result = f"// Call Relations: {call_relations}\n\n" + result

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result)
        
        return result

    # def map_lines_to_scopes(self, ast: ASTParser, slice_lines: set) -> dict:
    #     """
    #     /
        
    #     Args:
    #         ast: AST 
    #         slice_lines: 
            
    #     Returns:
    #         dict:  { (scope_type, scope_name, body_node): set(lines_in_scope) }
    #     """
    #     scope_mapping = {}
        
    #     # 
    #     func_nodes = ast.query("(function_definition)@func")
    #     method_nodes = ast.query("(method_declaration)@method")
        
    #     all_scopes = [node[0] for node in func_nodes + method_nodes]
        
    #     for scope_node in all_scopes:
    #         # 
    #         if scope_node.type == "function_definition":
    #             scope_type = "function"
    #             name_node = scope_node.child_by_field_name("name")
    #         else:
    #             scope_type = "method"
    #             name_node = scope_node.child_by_field_name("name")
            
    #         if name_node is None:
    #             continue
            
    #         scope_name = name_node.text.decode()
    #         body_node = scope_node.child_by_field_name("body")
    #         if body_node is None:
    #             continue
            
    #         # 
    #         scope_lines = set(range(body_node.start_point[0] + 1, body_node.end_point[0] + 1))
            
    #         # 
    #         lines_in_scope = slice_lines.intersection(scope_lines)
    #         if lines_in_scope:
    #             scope_mapping[(scope_type, scope_name, body_node)] = lines_in_scope
        
    #     return scope_mapping


    def map_lines_to_scopes(self, ast: ASTParser, slice_lines: set) -> dict:
        """
        ///

        Returns:
            dict:  { (scope_type, scope_name, body_node): set(lines_in_scope) }
        """
        scope_mapping = {}

        # ========== 1) / ==========
        func_nodes = ast.query("(function_definition)@func")
        method_nodes = ast.query("(method_declaration)@method")

        all_scopes = [node[0] for node in func_nodes + method_nodes]

        for scope_node in all_scopes:
            if scope_node.type == "function_definition":
                scope_type = "function"
            else:
                scope_type = "method"

            name_node = scope_node.child_by_field_name("name")
            if name_node is None:
                continue

            scope_name = name_node.text.decode(errors="ignore")
            body_node = scope_node.child_by_field_name("body")
            if body_node is None:
                continue

            # / +1/-1
            scope_lines = set(range(scope_node.start_point[0], scope_node.end_point[0] + 1))
            # scope_lines = set(range(body_node.start_point[0], body_node.end_point[0]) + 1)
            lines_in_scope = slice_lines.intersection(scope_lines)
            if lines_in_scope:
                scope_mapping[(scope_type, scope_name, scope_node)] = lines_in_scope

        # 
        covered = set().union(*scope_mapping.values()) if scope_mapping else set()

        # ========== 2)  ==========
        # 
        #  - namespace Foo { ... }
        #  - namespace Foo;  ( namespace )
        ns_query = ast.query("(namespace_definition)@ns")
        namespace_nodes = [n[0] for n in ns_query]

        for ns_node in namespace_nodes:
            # 
            ns_name_node = ns_node.child_by_field_name("name")
            ns_name = ns_name_node.text.decode(errors="ignore") if ns_name_node else "\\"

            #  body body
            ns_body = ns_node.child_by_field_name("body")
            if ns_body is not None:
                body_node = ns_body
                ns_lines = set(range(body_node.start_point[0] + 1, body_node.end_point[0] + 1))
            else:
                #  body namespace_definition 
                body_node = ns_node
                ns_lines = set(range(body_node.start_point[0], body_node.end_point[0] + 1))

            # /
            remaining = slice_lines - covered
            lines_in_scope = remaining.intersection(ns_lines)
            if lines_in_scope:
                scope_mapping[("namespace", ns_name, body_node)] = lines_in_scope
                covered |= lines_in_scope

        # ========== 3)  ==========
        # program 
        leftover = slice_lines - covered
        if leftover:
            prog_nodes = ast.query("(program)@prog")
            if prog_nodes:
                prog_node = prog_nodes[0][0]
                # program  "body"  body_node
                scope_mapping[("global", "<global>", prog_node)] = leftover

        return scope_mapping


    def ast_dive_php(self, root: Node, slice_lines: set[int]) -> set[int]:
        def is_in_node(line: int, node: Node) -> bool:
            node_start_line = node.start_point[0] + 1
            node_end_line = node.end_point[0] + 1
            return node_start_line <= line <= node_end_line
        
        def bubble_to_statement(node: Node) -> Node:
            """
             expression_statement
            
            """
            STOP_AT = {
                "expression_statement", "return_statement", "throw_statement",
                "global_declaration", "static_declaration"
            }
            p = node
            while p is not None and p.type not in STOP_AT:
                p = p.parent
            return p if p is not None else node

        slice_lines.update([root.start_point[0] + 1])
        slice_lines.update([root.end_point[0] + 1])
        for node in root.named_children:
            tmp_lines = set()
            node_start_line = node.start_point[0] + 1
            node_end_line = node.end_point[0] + 1
            for sline in slice_lines:
                if is_in_node(sline, node):     #  node 
                    tmp_lines.add(sline)
            if len(tmp_lines) == 0:
                continue

            if node.type == "expression_statement":
                slice_lines.update([line for line in range(node_start_line, node_end_line + 1)])
            elif node.type == "if_statement":
                condition_node = node.child_by_field_name("condition")
                if condition_node is None:
                    continue
                slice_lines.update([node_start_line])
                slice_lines.update([condition_node.start_point[0] + 1, condition_node.end_point[0] + 1])
                body_node = node.child_by_field_name("body")
                if body_node is None:
                    continue
                slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1]) #if {} 
                self.ast_dive_php(body_node, slice_lines)

                #  else if  else
                for i, alt in enumerate(node.children):
                    # print(node.field_name_for_child(i))
                    if node.field_name_for_child(i) != "alternative":
                        continue
                    if alt.type == "else_if_clause":
                        elseif_condition = alt.child_by_field_name("condition")
                        elseif_body = alt.child_by_field_name("body")
                        if elseif_condition is None or elseif_body is None:
                            continue
                        slice_lines.update([alt.start_point[0] + 1])
                        slice_lines.update([elseif_condition.start_point[0] + 1, elseif_condition.end_point[0] + 1])
                        slice_lines.update([elseif_body.start_point[0] + 1, elseif_body.end_point[0] + 1])
                        self.ast_dive_php(elseif_body, slice_lines)

                    elif alt.type == "else_clause":
                        else_body = alt.child_by_field_name("body")
                        if else_body is None:
                            continue
                        slice_lines.update([alt.start_point[0] + 1])
                        slice_lines.update([else_body.start_point[0] + 1, else_body.end_point[0] + 1])
                        self.ast_dive_php(else_body, slice_lines)

                # alternative_node = node.child_by_field_name("alternative")
                # if alternative_node is None:
                #     continue
                # next_alternative_node = alternative_node.child_by_field_name("alternative")
                # if next_alternative_node is None:
                #     slice_lines.update([alternative_node.start_point[0] + 1, alternative_node.end_point[0] + 1])
                # else:
                #     slice_lines.update([alternative_node.start_point[0] + 1])
                # self.ast_dive_php(alternative_node, slice_lines)
            elif node.type == "for_statement":
                body_node = node.child_by_field_name("body")
                if body_node is None:
                    continue
                slice_lines.update([node.start_point[0] + 1])
                slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1])
                self.ast_dive_php(body_node, slice_lines)
            elif node.type == "foreach_statement":
                body_node = node.child_by_field_name("body")
                if body_node is None:
                    continue
                slice_lines.update([node.start_point[0] + 1])
                slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1])
                self.ast_dive_php(body_node, slice_lines)
            elif node.type == "while_statement":
                body_node = node.child_by_field_name("body")
                if body_node is None:
                    continue
                slice_lines.update([node.start_point[0] + 1])
                slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1])
                self.ast_dive_php(body_node, slice_lines)
            elif node.type == "switch_statement":
                body_node = node.child_by_field_name("body")
                if body_node is None:
                    continue
                condition_node = node.child_by_field_name("condition")
                if condition_node is None:
                    continue
                slice_lines.update([condition_node.start_point[0] + 1, condition_node.end_point[0] + 1])
                slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1])
                self.ast_dive_php(body_node, slice_lines)
            elif node.type == "case_statement":
                slice_lines.add(node_start_line)
                self.ast_dive_php(node, slice_lines)
            elif node.type == "default_statement":
                slice_lines.add(node_start_line)
                self.ast_dive_php(node, slice_lines)
            elif node.type == "try_statement":
                body_node = node.child_by_field_name("body")
                if body_node is not None:
                    slice_lines.update([node.start_point[0] + 1])
                    slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1])
                    self.ast_dive_php(body_node, slice_lines)
            elif node.type == "catch_clause":
                body_node = node.child_by_field_name("body")
                if body_node is not None:
                    slice_lines.update([node.start_point[0] + 1])
                    slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1])
                    self.ast_dive_php(body_node, slice_lines)
            elif node.type == "finally_clause":
                body_node = node.child_by_field_name("body")
                if body_node is not None:
                    slice_lines.update([node.start_point[0] + 1])
                    slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1])
                    self.ast_dive_php(body_node, slice_lines)
            elif node.type == "compound_statement" or node.type == "declaration_list":
                slice_lines.update([node_start_line, node_end_line])
                self.ast_dive_php(node, slice_lines)
            else:
                slice_lines.update([line for line in range(node_start_line, node_end_line + 1)])
        
        if self.language == Language.PHP:
            slice_lines = set([lines for lines in slice_lines])
        return slice_lines


    def convert_backward_to_forward(self, backward_callpath):
        """
         callpath 
         direction  caller/callee 

        Args:
            backward_callpath (list[dict]): 

        Returns:
            list[dict]:  callpath
        """
        forward_callpath = []

        # 
        reversed_path = list(reversed(backward_callpath))
        reversed_path[-1]['direction'] = 'caller'  #  caller
        for item in reversed_path:
            new_item = {
                'call_site_nodeid': item['call_site_nodeid'],
                'call_site_code': item.get('call_site_code', ''),
                'location': item.get('location', {}),
                'param_pos': item.get('param_pos', ''),
                'funcid': item.get('funcid', ''),
            }

            direction = item.get('direction')

            if direction == 'caller':
                #  caller →  callee
                callee_name = item.get('caller_name', item.get('call_site_code', 'unknown'))
                new_item['callee_name'] = callee_name
                new_item['param_name'] = item.get('param_name', '')
                new_item['depth'] = item.get('level', 0)

            elif direction == 'callee':
                #  callee →  caller
                caller_name = item.get('callee_name', item.get('call_site_code', 'unknown'))
                new_item['caller_name'] = caller_name
                new_item['param_name'] = item.get('param_name', '')
                new_item['level'] = item.get('depth', 0)

            else:
                # 
                new_item.update(item)

            forward_callpath.append(new_item)

        return forward_callpath



    # def convert_backward_call_to_forward_call_path(self, backward_call_path):
    #     """
    #     
        
    #     Args:
    #         backward_call_path: 
            
    #     Returns:
    #         list: 
    #     """
    #     forward_call_path = []
    #     n = len(backward_call_path)
        
    #     for i in range(n - 1, -1, -1):
    #         current = backward_call_path[i]
    #         forward_entry = {}
            
    #         if 'caller_name' in current:
    #             #  caller callee
    #             forward_entry['callee_name'] = current['caller_name']
    #             forward_entry['call_site_nodeid'] = current['call_site_nodeid']
    #             forward_entry['param_name'] = current.get('param_name', '')
    #             forward_entry['param_pos'] = current.get('param_pos', '')
    #             forward_entry['taint_var'] = current.get('taint_var', '')
    #             forward_entry['depth'] = current.get('level', 0) + 1
    #         elif 'callee_name' in current:
    #             #  callee caller
    #             forward_entry['caller_name'] = current['callee_name']
    #             forward_entry['call_site_nodeid'] = current['call_site_nodeid']
    #             forward_entry['param_name'] = current.get('param_name', '')
    #             forward_entry['param_pos'] = current.get('param_pos', '')
    #             forward_entry['taint_var'] = current.get('taint_var', '')
    #             forward_entry['level'] = current.get('depth', 0) - 1
            
    #         forward_call_path.append(forward_entry)
        
    #     return forward_call_path


# 
def example_usage():
    """
    
    
    
    1.  start_node (860770)  build_graph_object_sql_having 
    2.  caller  ->  (862087)
    3.  automation_get_new_graphs_sql  callsite (857073)
    4.  caller  -> 
    5.  display_new_graphs  callsite (857361)  
    6.  callee  ->  callsite (857389)
    7.  db_fetch_assoc 0
    """
    
    # 
    call_path = [
        {
            'call_site_nodeid': 862087,  # 
            'call_site_code': 'return',
            'caller_name': 'build_graph_object_sql_having',
            'param_name': 'return',
            'param_pos': '',
            'taint_var': 'ret val',
            'level': 0,
        },
        {
            'call_site_nodeid': 857073,  # callsite 
            'call_site_code': 'build_graph_object_sql_having',
            'caller_name': 'automation_get_new_graphs_sql',
            'param_name': 'NOT_SUPPORT_FOR_AST_ASSIGN',
            'param_pos': '',
            'taint_var': 'ret val',
            'level': 1,
        },
        {
            'call_site_nodeid': 857361,  # callsite 
            'call_site_code': 'automation_get_new_graphs_sql',
            'caller_name': 'display_new_graphs',
            'param_name': 'NOT_SUPPORT_FOR_AST_ASSIGN',
            'param_pos': '',
            'taint_var': 'ret val',
            'level': 2,
        },
        {
            'call_site_nodeid': 857389,  # callsite 
            'call_site_code': 'db_fetch_assoc',
            'callee_name': 'db_fetch_assoc',
            'param_name': '$sql',
            'param_pos': 0,
            'taint_var': 'details',
            'depth': 1,
        }
    ]
    
    # ID
    start_node_id = 860770
    
    # 
    # slicer = InterproceduralForwardSlicer(analyzer)
    
    # 
    # slice_result = slicer.forward_slice(start_node_id, call_path)
    
    # print(f" {len(slice_result)} :")
    # print(slice_result)



#  node id 