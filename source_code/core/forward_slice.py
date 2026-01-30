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
        初始化跨函数前向切片器
        
        Args:
            analyzer: 包含 PDG 分析功能的分析器对象
        """
        self.analyzer = analyzer
        self.visited_nodes = set()
        self.slice_result = []
        self.language = Language.PHP
        # direction 表明了方向，是从 source 到 patch 还是 patch 到 sink
        self.direction = direction
        
    def forward_slice(self, call_path, patch_statements=[]):
        """
        执行跨函数前向切片
        
        Args:
            start_node_id: 切片起始节点ID
            call_path: 调用路径列表，每个元素是一个字典，包含调用信息
            
        Returns:
            list: 切片结果，包含所有相关节点ID
        """
        self.visited_nodes.clear()
        self.slice_result.clear()
        
        if not call_path:
            return self.slice_result
        
        # 先切 patch 所在的位置
        start_node_id = []
        backward_nodes = []
        for patch_stmt in patch_statements:
            start_node_id.append(patch_stmt['call_site_nodeid'])

        # 第一步: 从起始节点进行后向切片
        if start_node_id:
            backward_nodes = self._backward_slice_initial(start_node_id)

        # 第二步: 对每个后向切片收集到的节点进行前向切片
        for node_id in backward_nodes:
            # 先对 patch statement 和 backward slice 收集来的节点执行函数内切片
            self._slice_in_function(node_id)

        # 第三步：根据方向进行切片
        if self.direction == None:    # 默认是 patch 到 sink
            call_path.insert(0, patch_statements[0])  # 在路径开头插入 patch statement 信息
            self._forward_slice_from_node(node_id, call_path, 0)
        elif self.direction == "sp":
            if patch_statements:
                call_path.append(patch_statements[0])  # 在路径末尾插入 patch statement 信息
            self._forward_slice_from_node(call_path[0]['call_site_nodeid'], call_path, 0)

        return list(set(self.slice_result))  # 去重
    
    
    def forward_slice_intra(self, patch_statements=[]):
        """
        执行函数内的后向+前向切片
        
        Args:
            start_node_id: 切片起始节点ID
            
        Returns:
            list: 切片结果，包含所有相关节点ID
        """
        self.visited_nodes.clear()
        self.slice_result.clear()

        # 先切 patch 所在的位置
        start_node_id = []
        backward_nodes = []
        for patch_stmt in patch_statements:
            start_node_id.append(patch_stmt['call_site_nodeid'])

        # 第一步: 从起始节点进行后向切片
        if start_node_id:
            backward_nodes = self._backward_slice_initial(start_node_id)

        # 第二步: 对每个后向切片收集到的节点进行前向切片
        for node_id in backward_nodes:
            # 先对 patch statement 和 backward slice 收集来的节点执行函数内切片
            self._slice_in_function(node_id, patch_statements[-1]['call_site_nodeid'])

        return list(set(self.slice_result))  # 去重


    def forward_slice_source_patch(self, call_path, patch_statements=[]):
        """
        执行跨函数前向切片
        
        Args:
            start_node_id: 切片起始节点ID
            call_path: 调用路径列表，每个元素是一个字典，包含调用信息
            
        Returns:
            list: 切片结果，包含所有相关节点ID
        """
        self.visited_nodes.clear()
        self.slice_result.clear()
        
        if not call_path:
            return self.slice_result
    
        if self.direction == "sp":
            # if patch_statements:
            #     call_path.append(patch_statements[0])  # 在路径末尾插入 patch statement 信息
            self._forward_slice_from_node_source_patch(call_path[0]['call_site_nodeid'], call_path, 0)


        # 最后把 patch statement 所在的位置也切进去
        start_node_id = []
        backward_nodes = []
        for patch_stmt in patch_statements:
            start_node_id.append(patch_stmt['call_site_nodeid'])

        # 第一步: 从起始节点进行后向切片
        if start_node_id:
            backward_nodes = self._backward_slice_initial(start_node_id)

        # 第二步: 对每个后向切片收集到的节点进行前向切片
        for node_id in backward_nodes:
            # 先对 patch statement 和 backward slice 收集来的节点执行函数内切片
            self._slice_in_function(node_id)

        return list(set(self.slice_result))  # 去重
    

    def forward_slice_source_sink(self, call_path):
        """
        执行从source 到 sink 的跨函数前向切片
        
        Args:
            start_node_id: 切片起始节点ID
            call_path: 调用路径列表，每个元素是一个字典，包含调用信息
            
        Returns:
            list: 切片结果，包含所有相关节点ID
        """
        self.visited_nodes.clear()
        self.slice_result.clear()
        
        if not call_path:
            return self.slice_result
    
        if self.direction == "sp":
            # if patch_statements:
            #     call_path.append(patch_statements[0])  # 在路径末尾插入 patch statement 信息
            self._forward_slice_from_node_source_patch(call_path[0]['call_site_nodeid'], call_path, 0)

        # 切一下 source 的前面，如果有 check condition 要弄进来
        # self._slice_in_function(call_path[0]['call_site_nodeid'] - 300, call_path[0]['call_site_nodeid'])
        

        return list(set(self.slice_result))  # 去重

    
    def _backward_slice_initial(self, start_node_id):
        """
        在起始函数内进行后向切片,收集所有影响起始节点的节点
        
        Args:
            start_node_id: 起始节点ID
            first_path_item: 第一个路径项,用于确定函数范围
            
        Returns:
            list: 后向切片收集到的所有节点ID
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
            
            # 获取当前节点
            current_node = self.analyzer.get_node_itself(current_id)
            if not current_node:
                continue
            
            # 使用 PDG 的 def 关系进行后向遍历(找定义节点)
            ast_root = self.analyzer.get_ast_root_node(current_node)
            def_nodes = self.analyzer.pdg_step.find_def_nodes(ast_root)
            
            for def_node in def_nodes:
                def_id = def_node[NODE_INDEX]
                if def_id and def_id not in visited:
                    worklist.append(def_id)
        
        return backward_result
    

    def _forward_slice_from_node(self, start_node_id, call_path, path_index):
        """
        从指定节点开始,沿着调用路径进行前向切片
        
        Args:
            start_node_id: 当前起始节点ID
            call_path: 完整调用路径
            path_index: 当前处理的路径索引
        """
        current_node_id = start_node_id
        
        while path_index < len(call_path):
            current_path = call_path[path_index]
            
            # 查看下一个路径项,判断方向
            if path_index + 1 < len(call_path):
                next_path = call_path[path_index + 1]
                
                if 'caller_name' in next_path:
                    # 向上进入 caller: 从当前节点前向切片到返回值
                    function_name = current_path.get('caller_name', '')
                    # 在当前函数内切片到返回值
                    current_node_id = next_path['call_site_nodeid']
                    if next_path['level'] == current_path:
                        self._slice_in_function(current_node_id, current_node_id)
                    self._slice_in_function(current_node_id)
                    # 跨越函数边界: 返回值传播到 caller 的调用点
                    
                elif 'callee_name' in next_path:
                    # 向下进入 callee: 从当前节点前向切片到 callsite
                    callsite_node_id = next_path['call_site_nodeid']
                    function_name = current_path.get('callee_name', '')
                    self._slice_to_target(current_node_id, callsite_node_id, function_name)
                    
                    # 跨越函数边界: 参数传播到 callee 的形参
                    callee_name = next_path['callee_name']
                    param_pos = next_path.get('param_pos', 0)

                    callsite_node = self.analyzer.get_node_itself(callsite_node_id)
                    param_node_id = self._get_function_param_node(callsite_node, param_pos)
                
                    if param_node_id:
                        current_node_id = param_node_id
                    else:
                        # 无法找到形参,终止此路径
                        return
                
            else:
                # 最后一个路径项
                if 'caller_name' in current_path:
                    # 向上到 caller: 切片到返回值
                    return_node_id = current_path['call_site_nodeid']
                    function_name = current_path.get('caller_name', '')
                    self._slice_to_target(current_node_id, return_node_id, function_name)
                
                elif 'callee_name' in current_path:
                    # 最后一个路径项应该是不追的 最后一个的 callsite 只是在caller 中的 callsite，最后并没有记录进入callee 的callsite 了
                    pass

                    # 向下到 callee: 切片到函数末尾
                    # callee_name = current_path['callee_name']
                    # param_pos = current_path.get('param_pos', 0)
                    
                    # callsite_node = self.analyzer.get_node_itself(current_path['call_site_nodeid'])
                    # param_node_id = self._get_function_param_node(callsite_node, param_pos)

                    # if param_node_id:
                    #     # 在 callee 函数内进行完整的前向切片
                    #     self._slice_in_function(param_node_id, None)
            path_index += 1



    def _forward_slice_from_node_source_patch(self, start_node_id, call_path, path_index):
        """
        从指定节点开始,沿着调用路径进行前向切片
        
        Args:
            start_node_id: 当前起始节点ID
            call_path: 完整调用路径
            path_index: 当前处理的路径索引
        """
        current_node_id = start_node_id
        
        while path_index < len(call_path):
            current_path = call_path[path_index]
            
            # 查看下一个路径项,判断方向
            if path_index + 1 < len(call_path):
                next_path = call_path[path_index + 1]
                
                if 'caller_name' in next_path:
                    # 向上进入 caller: 从当前节点前向切片到返回值
                    function_name = current_path.get('caller_name', '')
                    # 在当前函数内切片到返回值
                    callersite_node_id = next_path['call_site_nodeid']

                    # 先收集当前切片中 current_node_id 的 backword initial node set
                    cur_backward_nodes = self._backward_slice_initial([current_node_id])

                    if next_path.get('level', -1) == current_path.get('level', -1):
                        self._slice_in_function(cur_backward_nodes, callersite_node_id)
                    else:
                        self._slice_in_function(cur_backward_nodes)
                    # 跨越函数边界: 返回值传播到 caller 的调用点
                    current_node_id = callersite_node_id
                    
                elif 'callee_name' in next_path:
                    # 向下进入 callee: 从当前节点前向切片到 callsite
                    callsite_node_id = next_path['call_site_nodeid']
                    function_name = current_path.get('callee_name', '')
                    if current_node_id != current_path["call_site_nodeid"]:
                        cur_backward_nodes = self._backward_slice_initial([current_node_id, current_path["call_site_nodeid"]])
                    else:
                        cur_backward_nodes = self._backward_slice_initial([current_node_id])
                    cur_backward_nodes = self._backward_slice_initial([current_node_id])
                    self._slice_to_target(cur_backward_nodes, callsite_node_id, function_name)
                    
                    # 跨越函数边界: 参数传播到 callee 的形参
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
                        # 无法找到形参,终止此路径
                        # TODO: 这里处理的也有点问题，形参中间可能会进行转换。对于sink 和 param 所在的函数来讲，还需要完整的后向+前向变量。对于其他部分来说需不需要呢？？
                        path_index += 1
                        continue
                
            else:
                # 最后一个路径项
                if 'caller_name' in current_path:
                    # 向上到 caller: 切片到返回值
                    return_node_id = current_path['call_site_nodeid']
                    function_name = current_path.get('caller_name', '')
                    cur_backward_nodes = self._backward_slice_initial([current_node_id])
                    
                    self._slice_to_target(cur_backward_nodes, return_node_id, function_name)
                
                elif 'callee_name' in current_path:
                    # 最后一个路径项应该是不追的 最后一个的 callsite 只是在caller 中的 callsite，最后并没有记录进入callee 的callsite 了
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

                    # 向下到 callee: 切片到函数末尾
                    # callee_name = current_path['callee_name']
                    # param_pos = current_path.get('param_pos', 0)
                    
                    # callsite_node = self.analyzer.get_node_itself(current_path['call_site_nodeid'])
                    # param_node_id = self._get_function_param_node(callsite_node, param_pos)

                    # if param_node_id:
                    #     # 在 callee 函数内进行完整的前向切片
                    #     self._slice_in_function(param_node_id, None)
            path_index += 1

    
    def _slice_to_target(self, start_node_id, target_node_id, function_name):
        """
        在函数内从起始节点前向切片到目标节点
        
        Args:
            start_node_id: 起始节点ID
            target_node_id: 目标节点ID（返回值或callsite）
            function_name: 当前函数名
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
            
            # 如果到达目标节点，继续但不再扩展
            if current_id >= target_node_id:
                continue
            
            # 获取当前节点
            current_node = self.analyzer.get_node_itself(current_id)
            if not current_node:
                continue
            
            # 使用 PDG 的 use 关系进行前向遍历
            ast_root = self.analyzer.get_ast_root_node(current_node)
            reach_to_nodes = self.analyzer.pdg_step.find_use_nodes(ast_root)
            
            for next_node in reach_to_nodes:
                next_id = next_node[NODE_INDEX]
                if next_id and next_id not in self.visited_nodes:
                    # 只添加在当前函数内且不超过目标节点的节点
                    if next_id <= target_node_id:
                        worklist.append(next_id)
    
    def _slice_in_function(self, start_node_id, end_node_id=None):
        """
        在函数内进行前向切片（不限制结束位置，或限制到end_node_id）
        
        Args:
            start_node_id: 起始节点ID
            function_name: 函数名
            end_node_id: 结束节点ID（可选）
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
            
            # 如果设置了结束节点且已到达，停止
            if end_node_id and current_id >= end_node_id:
                continue
            
            # 获取当前节点
            current_node = self.analyzer.get_node_itself(current_id)
            if not current_node:
                continue
            
            # 使用 PDG 的 use 关系进行前向遍历
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
        获取函数参数节点ID
        
        Args:
            function_name: 函数名
            param_pos: 参数位置（0-based）
            
        Returns:
            int: 参数节点ID
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
        将节点ID列表转换为代码（保持原始顺序）
        
        Args:
            node_ids: 节点ID列表（按遍历顺序）
            
        Returns:
            dict: 按文件组织的代码字典 {file_path: [(line_no, code, original_index), ...]}
        """
        # 收集所有节点的位置信息，保持原始顺序
        file_lines = {}  # {file_path: [(line_no, node_id, original_index), ...]}
        
        for idx, node_id in enumerate(node_ids):
            node = self.analyzer.get_node_itself(node_id)
            if node is None:
                continue
            
            # 获取行号
            line_no = node.get('lineno')
            if line_no is None:
                continue
            
            # 获取所属文件
            file_path = self.analyzer.fig_step.get_belong_file(node)
            if file_path is None:
                continue
            
            if file_path not in file_lines:
                file_lines[file_path] = []
            
            file_lines[file_path].append((line_no, node_id, idx))
        
        # 对每个文件进行处理
        result = {}
        for file_path, lines_list in file_lines.items():
            # 提取行号集合用于修复
            slice_lines = set([line_no for line_no, _, _ in lines_list])
            
            # 读取文件内容
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue
            
            # 使用 tree-sitter 修复代码
            fixed_lines = self._fix_code_with_treesitter(file_content, slice_lines, file_path)
            
            # 提取修复后的代码，保持原始遍历顺序
            file_lines_list = file_content.split('\n')
            result[file_path] = []
            
            # 提取修复后的代码，保持原始遍历顺序
            for scope_name, lines_in_scope in fixed_lines.items():
                scope_code = [file_lines_list[l - 1] for l in sorted(lines_in_scope)]
                result[file_path].append((scope_name, scope_code))

        return result

    def _fix_code_with_treesitter(self, code, slice_lines, file_path):
        """
        使用 tree-sitter 修复代码切片，移除不完整的语法结构
        
        Args:
            code: 完整的文件代码
            slice_lines: 切片包含的行号集合
            file_path: 文件路径
            
        Returns:
            set: 修复后的行号集合
        """

        # 解析 AST
        ast = ASTParser(code, self.language)
        
        # 将切片行映射到对应的函数/方法
        scope_mapping = self.map_lines_to_scopes(ast, slice_lines)
        
        # 对每个作用域分别修复
        all_fixed_lines: dict[str, set[int]] = {}
        
        for scope_info, lines_in_scope in scope_mapping.items():
            scope_type, scope_name, body_node = scope_info
            
            # 修复该作用域内的代码
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
        修复 if 语句：如果 if 的 body 完全不在切片中，移除整个 if 语句
        """
        # 查询所有 if 语句
        if_nodes = ast_parser.query_from_node(root, "(if_statement)@if")
        if_nodes = [node[0] for node in if_nodes if node[0].type == "if_statement"]
        
        for if_node in if_nodes:
            # 跳过 else if 中的 if
            if if_node.parent is not None and if_node.parent.type == "else_clause":
                continue
            
            condition_node = if_node.child_by_field_name("condition")
            consequence_node = if_node.child_by_field_name("body")
            
            if condition_node is None or consequence_node is None:
                continue
            
            # 计算各部分的行号范围
            if_node_lines = set(range(if_node.start_point[0] + 1, if_node.end_point[0] + 2))
            condition_lines = set(range(condition_node.start_point[0] + 1, condition_node.end_point[0] + 2))
            consequence_lines = set(range(consequence_node.start_point[0] + 1, consequence_node.end_point[0] + 1))
            
            # 如果 consequence 以 { 开始，排除第一行
            if consequence_node.text is not None and consequence_node.text.decode().startswith("{\n"):
                consequence_lines -= {consequence_node.start_point[0] + 1}
            
            # 如果 consequence 完全不在切片中，移除整个 if 语句
            if len(consequence_lines.intersection(slice_lines)) == 0:
                slice_lines -= if_node_lines
        
        return slice_lines
    
    def _trim_loops(self, ast_parser, root, slice_lines):
        """
        修复循环语句（for, while, foreach, do-while）
        """
        # 查询各种循环
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
                    # 尝试查找其他可能的 body 字段
                    for child in loop_node.children:
                        if child.type == "compound_statement":
                            body_node = child
                            break
                
                if body_node is None:
                    continue
                
                # 计算 body 的行号范围
                body_lines = set(range(body_node.start_point[0] + 1, body_node.end_point[0] + 1))
                
                # 如果 body 以 { 开始，排除第一行
                if body_node.text is not None and body_node.text.decode().startswith("{\n"):
                    body_lines -= {body_node.start_point[0] + 1}
                
                # 如果 body 完全不在切片中，移除整个循环
                if len(body_lines.intersection(slice_lines)) == 0:
                    loop_lines = set(range(loop_node.start_point[0] + 1, loop_node.end_point[0] + 2))
                    slice_lines -= loop_lines
        
        return slice_lines
    
    def _trim_switch_statements(self, ast_parser, root, slice_lines):
        """
        修复 switch 语句：移除空的 case 分支
        """
        switch_nodes = ast_parser.query_from_node(root, "(switch_statement)@switch")
        switch_nodes = [node[0] for node in switch_nodes if node[0].type == "switch_statement"]
        
        for switch_node in switch_nodes:
            # 查找所有 case 和 default
            case_nodes = []
            for child in switch_node.children:
                if child.type in ["case_statement", "default_statement"]:
                    case_nodes.append(child)
            
            for case_node in case_nodes:
                # 获取 case 的所有行
                case_lines = set(range(case_node.start_point[0] + 1, case_node.end_point[0] + 2))
                
                # 获取 case 标签行
                case_label_line = case_node.start_point[0] + 1
                
                # 获取 case body 的行（排除标签行）
                case_body_lines = case_lines - {case_label_line}
                
                # 如果 case body 完全不在切片中，移除整个 case
                if len(case_body_lines.intersection(slice_lines)) == 0:
                    slice_lines -= case_lines
        
        return slice_lines
    
    def _trim_try_catch(self, ast_parser, root, slice_lines):
        """
        修复 try-catch 语句
        """
        try_nodes = ast_parser.query_from_node(root, "(try_statement)@try")
        try_nodes = [node[0] for node in try_nodes if node[0].type == "try_statement"]
        
        for try_node in try_nodes:
            body_node = try_node.child_by_field_name("body")
            if body_node is None:
                continue
            
            # 计算 try body 的行号范围
            body_lines = set(range(body_node.start_point[0] + 1, body_node.end_point[0] + 1))
            
            # 如果 try body 完全不在切片中，移除整个 try 语句
            if len(body_lines.intersection(slice_lines)) == 0:
                try_lines = set(range(try_node.start_point[0] + 1, try_node.end_point[0] + 2))
                slice_lines -= try_lines
            else:
                # 检查 catch 块
                catch_nodes = [child for child in try_node.children if child.type == "catch_clause"]
                for catch_node in catch_nodes:
                    catch_body = catch_node.child_by_field_name("body")
                    if catch_body is None:
                        continue
                    
                    catch_body_lines = set(range(catch_body.start_point[0] + 1, catch_body.end_point[0] + 1))
                    
                    # 如果 catch body 完全不在切片中，移除该 catch
                    if len(catch_body_lines.intersection(slice_lines)) == 0:
                        catch_lines = set(range(catch_node.start_point[0] + 1, catch_node.end_point[0] + 2))
                        slice_lines -= catch_lines
        
        return slice_lines
    
    def _trim_blocks(self, ast_parser, root, slice_lines):
        """
        修复空的代码块：如果一个 compound_statement 完全为空，移除它
        """
        block_nodes = ast_parser.query_from_node(root, "(compound_statement)@block")
        block_nodes = [node[0] for node in block_nodes if node[0].type == "compound_statement"]
        
        for block_node in block_nodes:
            # 获取块的所有行
            block_lines = set(range(block_node.start_point[0] + 1, block_node.end_point[0] + 2))
            
            # 排除开头和结尾的大括号行
            block_start = block_node.start_point[0] + 1
            block_end = block_node.end_point[0] + 1
            block_content_lines = block_lines - {block_start, block_end}
            
            # 如果块内容完全不在切片中，移除整个块
            if len(block_content_lines.intersection(slice_lines)) == 0:
                # 检查父节点类型，某些情况下需要保留
                if block_node.parent and block_node.parent.type not in ["function_definition", "method_declaration"]:
                    slice_lines -= block_lines
        
        return slice_lines

    def extract_path(self, full_path: str) -> str:
        prefix = "./projects/"
        
        if not full_path.startswith(prefix):
            return full_path  # 不符合你的规则，原样返回或你也可以 return None

        rest = full_path[len(prefix):]           # 去掉固定前缀
        return rest.split("/", 1)[1]              # 去掉第一个目录（CVE-xxxx）
    
    def export_slice_code(self, node_ids, output_file=None, call_relations=None):
        """
        导出切片代码到文件或返回字符串
        
        Args:
            node_ids: 节点ID列表
            output_file: 输出文件路径（可选）
            
        Returns:
            str: 格式化的切片代码
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
                output_lines.append("\n")  # 添加空行分隔不同作用域

        result = '\n'.join(output_lines)
        
        if call_relations is not None:
            result = f"// Call Relations: {call_relations}\n\n" + result

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result)
        
        return result

    # def map_lines_to_scopes(self, ast: ASTParser, slice_lines: set) -> dict:
    #     """
    #     将切片行映射到对应的函数/方法作用域
        
    #     Args:
    #         ast: AST 解析器对象
    #         slice_lines: 切片包含的行号集合
            
    #     Returns:
    #         dict: 作用域映射 { (scope_type, scope_name, body_node): set(lines_in_scope) }
    #     """
    #     scope_mapping = {}
        
    #     # 查询所有函数和方法定义
    #     func_nodes = ast.query("(function_definition)@func")
    #     method_nodes = ast.query("(method_declaration)@method")
        
    #     all_scopes = [node[0] for node in func_nodes + method_nodes]
        
    #     for scope_node in all_scopes:
    #         # 获取作用域类型和名称
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
            
    #         # 计算作用域内的行号范围
    #         scope_lines = set(range(body_node.start_point[0] + 1, body_node.end_point[0] + 1))
            
    #         # 找出切片中属于该作用域的行
    #         lines_in_scope = slice_lines.intersection(scope_lines)
    #         if lines_in_scope:
    #             scope_mapping[(scope_type, scope_name, body_node)] = lines_in_scope
        
    #     return scope_mapping


    def map_lines_to_scopes(self, ast: ASTParser, slice_lines: set) -> dict:
        """
        将切片行映射到对应的函数/方法/命名空间/全局作用域

        Returns:
            dict: 作用域映射 { (scope_type, scope_name, body_node): set(lines_in_scope) }
        """
        scope_mapping = {}

        # ========== 1) 函数/方法 ==========
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

            # 计算函数/方法体行号（包含起止行；你也可以按需调整 +1/-1）
            scope_lines = set(range(scope_node.start_point[0], scope_node.end_point[0] + 1))
            # scope_lines = set(range(body_node.start_point[0], body_node.end_point[0]) + 1)
            lines_in_scope = slice_lines.intersection(scope_lines)
            if lines_in_scope:
                scope_mapping[(scope_type, scope_name, scope_node)] = lines_in_scope

        # 已覆盖的行
        covered = set().union(*scope_mapping.values()) if scope_mapping else set()

        # ========== 2) 命名空间作用域（若存在） ==========
        # 兼容两种写法：
        #  - 带花括号：namespace Foo { ... }
        #  - 不带花括号：namespace Foo;  (直到下一个 namespace 或文件末尾)
        ns_query = ast.query("(namespace_definition)@ns")
        namespace_nodes = [n[0] for n in ns_query]

        for ns_node in namespace_nodes:
            # 命名空间名
            ns_name_node = ns_node.child_by_field_name("name")
            ns_name = ns_name_node.text.decode(errors="ignore") if ns_name_node else "\\"

            # 优先取 body（大括号形式会有 body）
            ns_body = ns_node.child_by_field_name("body")
            if ns_body is not None:
                body_node = ns_body
                ns_lines = set(range(body_node.start_point[0] + 1, body_node.end_point[0] + 1))
            else:
                # 无大括号形式：没有 body，就使用整个 namespace_definition 节点范围作为保守近似
                body_node = ns_node
                ns_lines = set(range(body_node.start_point[0], body_node.end_point[0] + 1))

            # 只统计尚未覆盖的切片行，避免与函数/方法重叠
            remaining = slice_lines - covered
            lines_in_scope = remaining.intersection(ns_lines)
            if lines_in_scope:
                scope_mapping[("namespace", ns_name, body_node)] = lines_in_scope
                covered |= lines_in_scope

        # ========== 3) 全局作用域（文件顶层） ==========
        # program 节点代表文件根；把未被覆盖的切片行都归入全局
        leftover = slice_lines - covered
        if leftover:
            prog_nodes = ast.query("(program)@prog")
            if prog_nodes:
                prog_node = prog_nodes[0][0]
                # program 本身没有 "body" 字段，直接用它做 body_node
                scope_mapping[("global", "<global>", prog_node)] = leftover

        return scope_mapping


    def ast_dive_php(self, root: Node, slice_lines: set[int]) -> set[int]:
        def is_in_node(line: int, node: Node) -> bool:
            node_start_line = node.start_point[0] + 1
            node_end_line = node.end_point[0] + 1
            return node_start_line <= line <= node_end_line
        
        def bubble_to_statement(node: Node) -> Node:
            """
            向上冒泡直到找到语句级节点（如 expression_statement）。
            如果没找到则返回自己。
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
                if is_in_node(sline, node):     # 看切片行是否在当前 node 的范围内
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
                slice_lines.update([body_node.start_point[0] + 1, body_node.end_point[0] + 1]) #把if的 {} 加入进来
                self.ast_dive_php(body_node, slice_lines)

                # 处理后面的 else if 和 else
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
        将后向遍历得到的 callpath 转换为前向遍历格式。
        会反转顺序，并对 direction 进行 caller/callee 翻转。

        Args:
            backward_callpath (list[dict]): 后向遍历结果

        Returns:
            list[dict]: 转换后的前向遍历 callpath
        """
        forward_callpath = []

        # 反转路径顺序（因为后向是反的）
        reversed_path = list(reversed(backward_callpath))
        reversed_path[-1]['direction'] = 'caller'  # 起始点默认进入 caller
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
                # 后向表示 caller → 前向应该进入 callee
                callee_name = item.get('caller_name', item.get('call_site_code', 'unknown'))
                new_item['callee_name'] = callee_name
                new_item['param_name'] = item.get('param_name', '')
                new_item['depth'] = item.get('level', 0)

            elif direction == 'callee':
                # 后向表示 callee → 前向应该返回 caller
                caller_name = item.get('callee_name', item.get('call_site_code', 'unknown'))
                new_item['caller_name'] = caller_name
                new_item['param_name'] = item.get('param_name', '')
                new_item['level'] = item.get('depth', 0)

            else:
                # 其他未知方向，保留原状
                new_item.update(item)

            forward_callpath.append(new_item)

        return forward_callpath



    # def convert_backward_call_to_forward_call_path(self, backward_call_path):
    #     """
    #     将后向调用路径转换为前向调用路径
        
    #     Args:
    #         backward_call_path: 后向调用路径列表
            
    #     Returns:
    #         list: 前向调用路径列表
    #     """
    #     forward_call_path = []
    #     n = len(backward_call_path)
        
    #     for i in range(n - 1, -1, -1):
    #         current = backward_call_path[i]
    #         forward_entry = {}
            
    #         if 'caller_name' in current:
    #             # 当前是 caller，前向路径中为 callee
    #             forward_entry['callee_name'] = current['caller_name']
    #             forward_entry['call_site_nodeid'] = current['call_site_nodeid']
    #             forward_entry['param_name'] = current.get('param_name', '')
    #             forward_entry['param_pos'] = current.get('param_pos', '')
    #             forward_entry['taint_var'] = current.get('taint_var', '')
    #             forward_entry['depth'] = current.get('level', 0) + 1
    #         elif 'callee_name' in current:
    #             # 当前是 callee，前向路径中为 caller
    #             forward_entry['caller_name'] = current['callee_name']
    #             forward_entry['call_site_nodeid'] = current['call_site_nodeid']
    #             forward_entry['param_name'] = current.get('param_name', '')
    #             forward_entry['param_pos'] = current.get('param_pos', '')
    #             forward_entry['taint_var'] = current.get('taint_var', '')
    #             forward_entry['level'] = current.get('depth', 0) - 1
            
    #         forward_call_path.append(forward_entry)
        
    #     return forward_call_path


# 使用示例
def example_usage():
    """
    使用示例
    
    调用路径解读：
    1. 从 start_node (860770) 开始，在 build_graph_object_sql_having 函数中
    2. 下一个是 caller 方向 -> 切片到返回值 (862087)
    3. 进入 automation_get_new_graphs_sql 函数的 callsite (857073)
    4. 下一个是 caller 方向 -> 切片到返回值
    5. 进入 display_new_graphs 函数的 callsite (857361)  
    6. 下一个是 callee 方向 -> 切片到 callsite (857389)
    7. 进入 db_fetch_assoc 函数，从第0个参数开始切片
    """
    
    # 调用路径
    call_path = [
        {
            'call_site_nodeid': 862087,  # 返回值位置
            'call_site_code': 'return',
            'caller_name': 'build_graph_object_sql_having',
            'param_name': 'return',
            'param_pos': '',
            'taint_var': 'ret val',
            'level': 0,
        },
        {
            'call_site_nodeid': 857073,  # callsite 位置
            'call_site_code': 'build_graph_object_sql_having',
            'caller_name': 'automation_get_new_graphs_sql',
            'param_name': 'NOT_SUPPORT_FOR_AST_ASSIGN',
            'param_pos': '',
            'taint_var': 'ret val',
            'level': 1,
        },
        {
            'call_site_nodeid': 857361,  # callsite 位置
            'call_site_code': 'automation_get_new_graphs_sql',
            'caller_name': 'display_new_graphs',
            'param_name': 'NOT_SUPPORT_FOR_AST_ASSIGN',
            'param_pos': '',
            'taint_var': 'ret val',
            'level': 2,
        },
        {
            'call_site_nodeid': 857389,  # callsite 位置
            'call_site_code': 'db_fetch_assoc',
            'callee_name': 'db_fetch_assoc',
            'param_name': '$sql',
            'param_pos': 0,
            'taint_var': 'details',
            'depth': 1,
        }
    ]
    
    # 起始节点ID
    start_node_id = 860770
    
    # 创建切片器
    # slicer = InterproceduralForwardSlicer(analyzer)
    
    # 执行前向切片
    # slice_result = slicer.forward_slice(start_node_id, call_path)
    
    # print(f"切片结果包含 {len(slice_result)} 个节点:")
    # print(slice_result)



# 再实现一个 node id 到代码的转化器，再加一个语义修复的