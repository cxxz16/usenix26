import logging
import pickle
from platform import node
import json
import os.path
from typing import Dict, List, Set, Tuple, Union
import networkx as nx
import py2neo
import matplotlib.pyplot as plt
from typing import List
from config.path import STORAGE_PATH
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.modified_line import ModifiedLine
from core.anchor_node import AnchorNode
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.ast2code import Ast2CodeFactory
from core.chat import openai_chat
logger = logging.getLogger(__name__)

# TYPE_NEW 好像会把所有当前函数内的东西调用都来一遍？暂时先去了  非常耗时
COMMON_NODE_TYPES = [
        TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL,
        TYPE_INCLUDE_OR_EVAL,
        TYPE_ECHO, TYPE_PRINT, TYPE_EXIT
]

class CacheCenter(object):
    def __init__(self):
        self.already_traversal_node = {}
        self.already_detect_functions = {}
        self.already_visit_pdg_node = set()
        self.already_taint_edge: List[Tuple] = []

        self.cg_cache_graph = nx.DiGraph()
        # self.patch_cache_graph = dict()
        
        self.ceg_cache_dict = dict()

    def clear_cache(self):
        self.__init__()

    def update_already_taint_edge(self, start, end):
        self.already_taint_edge.append((start, end))
        self.already_taint_edge.sort(key=lambda x: x[0])

    def is_taint_by_cfg(self, node_id):
        for _range in self.already_taint_edge:
            if _range[0] <= node_id <= _range[1]:
                return True
        return False

    def update_already_detect_functions(self, node_hash, value):
        if node_hash not in self.already_detect_functions.keys():
            self.already_detect_functions[node_hash] = value
        else:
            self.already_detect_functions[node_hash] = value | self.already_detect_functions[node_hash]


class ContextSlicer(object):
    def __init__(self, anchor_node: AnchorNode, analyzer: Neo4jEngine, commit_id=None, cve_id=None, vuln_type=None, max_caller_depth=1, max_callee_depth=1):
        self.analyzer = analyzer
        self.anchor_node = anchor_node
        self.commit_id = commit_id if commit_id is not None else 'uk'
        self.anchor_node_ast = None
        self.anchor_node_root = None
        self.far_node = None
        self.pdg_digraph = nx.DiGraph()
        self.sources = set()
        self.custom_sources = set()
        self.taint_param = set()
        self.cve_id = cve_id
        self.vuln_type = vuln_type
        self.__backup_anchor_node_id = -1
        self.__cache_center = CacheCenter()
        self.potential_source_funcname = set()

        self.max_callee_direction_depth = max_callee_depth
        self.max_caller_direction_level = max_caller_depth

        self.backward_call_stack = []  # backward方向的调用栈
        self.backward_call_paths = []  # 记录所有完整的backward调用路径
        self.collected_backward_callsites = []  # 收集的所有callsite
        self.already_processed_backward_callsite = set()  # 避免重复处理
        self.nodeid_to_callname_cache = dict()  # nodeid 到 callname 的缓存
        

    def clear_cache(self):
        self.anchor_node_ast = None
        self.anchor_node_root = None
        self.far_node = None
        self.pdg_digraph = nx.DiGraph()
        self.sources = set()
        self.taint_param = set()

    def load_backward_paths(self):
        filepath = os.path.join(STORAGE_PATH, 'cve_source_finder', f'all_paths_{self.cve_id}_{self.commit_id}.pkl')
        if not os.path.exists(filepath):
            return False
        with open(filepath, 'rb') as f:
            self.backward_call_paths = pickle.load(f)
        if self.backward_call_paths is not None:
            return True
        else:
            return False
        
    def _is_duplicate_path(self, new_paths, old_paths):
        """检查路径是否已存在，这部分效率低，后续可以优化"""            
        for new_path in new_paths:
            for existing_path in old_paths:
                if self._paths_equal(existing_path, new_path):
                    return True
        return False
    
    def _paths_equal(self, path1, path2):
        """比较两条路径是否相同"""
        if len(path1) != len(path2):
            return False
        
        # 先用 call_site_id 做比较
        for i in range(len(path1)):
            if (path1[i]['call_site_code'] != path2[i]['call_site_code'] or
                path1[i]['callee_name'] != path2[i]['callee_name']) or \
                path1[i]['call_site_nodeid'] != path2[i]['call_site_nodeid']:
                return False
        
        return True

    # def load_sinks(self) -> bool:
    #     if os.path.exists(self.sink_storage_path):
    #         with open(self.sink_storage_path, "r") as f:
    #             sink_list = json.load(f)
    #         for node_dict in sink_list:
    #             node = self.analyzer.get_node_itself(node_dict['id'])
    #             self.potential_anchor_nodes.add_without_check(
    #                 AnchorNode.from_node_instance(
    #                     node, judge_type=node_dict['judge_type'], param_loc=node_dict['loc'],
    #                     git_repository=self.git_repository,
    #                     version=f"{self.patch_commit_id}_prepatch",
    #                     func_name=self.analyzer.code_step.get_node_code(node), 
    #                     file_name=self.analyzer.fig_step.get_belong_file(node),
    #                     cve_id=self.cve_id
    #                 )
    #             )
    #         return True
    #     else:
    #         return False
        
    def load_all_paths(self):
        # 使用 pickle 加载 self.all_paths
        try:
            with open(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), f'all_paths_{self.cve_id}_{self.commit_id}.pkl'), 'rb') as f:
                self.backward_call_paths = pickle.load(f)

            with open(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), f'all_potential_source_funcname_{self.cve_id}_{self.commit_id}.pkl'), 'rb') as f:
                self.potential_source_funcname = pickle.load(f)

            with open(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), f'all_builtin_source_{self.cve_id}_{self.commit_id}.pkl'), 'rb') as f:
                self.sources = set(pickle.load(f))
            
            print(f"[+] Load existing paths and potential source function names for CVE {self.cve_id}, commit {self.commit_id}.")
            return True
        except FileNotFoundError:
            return False
        
    def print_call_paths(self, paths):
        """
        打印调用路径列表。
        `paths` 可以是：
        - 单条路径(list[dict])
        - 多条路径(list[list[dict]])
        每个 dict 至少包含：
        - call_site_code
        - direction: 'caller' 或 'callee'
        - depth (callee 段) / level (caller 段，可选)
        - callee_name
        - location: {'file': ..., 'line': ...}（可选）
        - param_pos / marker 等字段视情况展示
        """

        # 如果传进来的是单条路径（list[dict]），转成 list[list[dict]]
        if paths and isinstance(paths[0], dict):
            all_paths = [paths]
        else:
            all_paths = paths

        print(f"\n=== 发现 {len(all_paths)} 条调用路径 ===\n")

        for idx, path in enumerate(all_paths, 1):
            print(f"路径 {idx}:")
            if not path:
                print("  (空路径)\n")
                continue

            # 统计 caller / callee 段的元素数量，用于缩进计算
            caller_len = sum(1 for c in path if c.get("direction") == "caller")
            callee_len = sum(1 for c in path if c.get("direction") == "callee")

            segment = None  # 当前段类型：'caller' 或 'callee'
            caller_idx = 0
            callee_idx = 0

            for call in path:
                curr = call.get("direction", "callee")  # 默认当成 callee
                if curr not in ("caller", "callee"):
                    curr = "callee"

                # 段切换时打印一个小标题
                if curr != segment:
                    segment = curr
                    header = "↑ Caller 段（向上溯源）" if segment == "caller" else "↓ Callee 段（向下深入）"
                    print(f"  {header}")

                # 计算缩进层级
                if segment == "caller":
                    # caller 段逆向递减缩进：最靠近污点的调用缩进最少
                    indent_level = max(0, (caller_len - 1 - caller_idx))
                else:
                    # callee 段正向递增缩进：越往下越深
                    # 优先使用 depth 字段，没有就用 callee_idx
                    indent_level = call.get("depth", callee_idx)

                indent = "    " * indent_level

                # 生成标签（tag）
                if segment == "caller":
                    lvl = call.get("level", caller_idx)
                    tag = f"Caller L{lvl}"
                    name = call.get("caller_name", "<unknown_caller>")
                else:
                    depth = call.get("depth", callee_idx)
                    tag = f"Callee D{depth}"
                    name = call.get("callee_name", "<unknown_callee>")

                code = call.get("call_site_code", "<unknown_call_site>")

                # 第一行：调用点代码
                print(f"{indent}[{tag}] {code}")

                # 第二行：进入函数的描述（当前数据里只有 callee_name）
                marker = call.get("marker")
                marker_str = f" [标记: {marker}]" if marker else ""
                param_pos = call.get("param_pos")
                if param_pos is not None and param_pos >= 0:
                    param_str = f"param_pos={param_pos}"
                else:
                    param_str = ""

                if segment == "caller":
                    direction_text = "进入上层函数"
                else:
                    direction_text = "进入被调函数"

                extra = ", ".join(x for x in [param_str] if x)
                extra = f" ({extra})" if extra else ""

                print(f"{indent}  └─> {direction_text} {name}{extra}{marker_str}")

                # 位置信息
                loc = call.get("location")
                if isinstance(loc, dict):
                    print(f"{indent}      @ {loc.get('file', '?')}:{loc.get('line', '?')}")

                # 递增计数器
                if segment == "caller":
                    caller_idx += 1
                else:
                    callee_idx += 1

            print()  # 路径结束空一行


    def print_potential_source_funcname(self):
        """打印所有潜在的 source 函数名"""
        print(f"\n=== 发现 {len(self.potential_source_funcname)} 个潜在 source 函数名 ===\n")
        for funcname in self.potential_source_funcname:
            print(f"- {funcname}")
        print()

    def print_builtin_sources(self):
        """打印所有内置 source 节点"""
        print(f"\n=== 发现 {len(self.sources)} 个内置 source 节点 ===\n")
        for src in self.sources:
            print(f"- 节点ID: {src}")
        print()


    
    def find_function_arg_node_list_1127(self, node):
        if node[NODE_TYPE] not in [TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL, TYPE_NEW, TYPE_ECHO, TYPE_PRINT, TYPE_INCLUDE_OR_EVAL, TYPE_EXIT, TYPE_FUNC_DECL, TYPE_METHOD, TYPE_RETURN, TYPE_EMPTY]:
            print(f"[-] Warning: Node {node[NODE_INDEX]} is not a function/method call or declaration.")
            return "()"
        arg_str = "("
        # 只找到当前层的 arg_list
        args_list_node = self.analyzer.ast_step.find_child_nodes(
            node,
            include_type=[TYPE_ARG_LIST]
        )
        if args_list_node.__len__() == 0:
            arg_str += ")"
            return arg_str
        args_list_node = args_list_node[0]
        
        args_nodes = self.analyzer.ast_step.find_child_nodes(args_list_node)
        for args_node in args_nodes:

            if args_node[NODE_TYPE] in {TYPE_VAR}:
                code = self.analyzer.code_step.get_node_code(args_node)
                arg_str += f"{code}, "

            elif args_node[NODE_TYPE] in {TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
                call_node_name = self.get_method_call_name(args_node)
                args = self.find_function_arg_node_list_1127(args_node)
                arg_str += f"{call_node_name}{args}, "

            elif args_node[NODE_TYPE] in {TYPE_ARRAY}:
                array_flag = args_node['flags']
                if ARRAY_SYNTAX_LONG not in array_flag:
                    print(f"[-] Warning: Unexpected array syntax for node {args_node[NODE_INDEX]}.")
                    arg_str += "array(...), "
                    continue
                array_elems_node = self.analyzer.ast_step.find_child_nodes(
                    args_node,
                    include_type=[TYPE_ARRAY_ELEM]
                )
                array_str = "array("

                for elem in array_elems_node:
                    values_node = self.analyzer.ast_step.find_child_nodes(
                        elem,
                        include_type=None
                    )
                    values_node = sorted(values_node, key=lambda x: x[NODE_INDEX], reverse=True)
                    key, value = "", ""
                    assert values_node.__len__() == 2
                    for idx, value_node in enumerate(values_node):
                        if value_node[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
                            call_node_name = self.get_method_call_name(value_node)
                            args = self.find_function_arg_node_list_1127(value_node)
                            if idx == 0:
                                key = f"{call_node_name}{args}"
                            else:
                                value = f"{call_node_name}{args}"
                        else:
                            code = self.analyzer.code_step.get_node_code(value_node)
                            if not code.startswith('$'):
                                code = f"'{code}'"
                            if idx == 0:
                                key = code
                            else:
                                value = code
                    array_str += f"{key} => {value}, "
                array_str = array_str[:-2] + "), " if array_str.endswith(", ") else array_str + "), "
                arg_str += array_str
            else:
                code = self.analyzer.code_step.get_node_code(args_node)
                arg_str += f"{code}, "

        arg_str = arg_str[:-2] + ")" if arg_str.endswith(", ") else arg_str + ")"
        return arg_str


    def run(self, state="PATCH"):
        self.context_series = list()
        # if self.load_backward_paths():
        #     return self.context_series
        # 这里需要插入个状态，分别是 patch 还是 sink
        if state == "PATCH":
            
            if self.load_all_paths():
                self.print_call_paths(self.backward_call_paths)
                self.print_potential_source_funcname()
                self.print_builtin_sources()
                return self.context_series

            self.patch_analysis_result: Dict[str, List[ModifiedLine]] = \
                json.load(object_hook=lambda x: ModifiedLine(**x) if 'lineno' in x.keys() else x,
                        fp=open(os.path.join(STORAGE_PATH, 'patch_analysis_result', "results", f'res_{self.commit_id}.json')))
            # self.__backup_anchor_node_id = self.anchor_node.node_id

            for file, affect_line in self.patch_analysis_result.items():
                for affect_node in affect_line:
                    self.anchor_node.node_id = affect_node.root_node
                    self.do_backward_slice()

        elif state == "DETECTION":
            if self.load_all_paths():
                self.print_call_paths(self.backward_call_paths)
                self.print_potential_source_funcname()
                self.print_builtin_sources()
                return self.context_series

            self.do_backward_slice()        # 收集调用 callsite


        for node_hash in self.__cache_center.already_detect_functions.keys():
            node_id, func_name = node_hash.split("::", 1)
            node_id = int(node_id)
            node = self.analyzer.get_node_itself(node_id)
            func_args_str = self.find_function_arg_node_list_1127(node)
            func_signature = func_name + func_args_str
            self.potential_source_funcname.add(func_signature)

        os.makedirs(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type)), exist_ok=True)
        with open(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), f'all_paths_{self.cve_id}_{self.commit_id}.pkl'), 'wb') as f:
            pickle.dump(self.backward_call_paths, f)

        with open(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), f'all_potential_source_funcname_{self.cve_id}_{self.commit_id}.pkl'), 'wb') as f:
            pickle.dump(self.potential_source_funcname, f)

        with open(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), f'all_builtin_source_{self.cve_id}_{self.commit_id}.pkl'), 'wb') as f:
            pickle.dump(self.sources, f)

        return self.context_series


        # exit(0)
        if self.sources.__len__() == 0:
            self.do_find_extend_source()
        self.do_forward_path_exploration()
        self.anchor_node.node_id = self.__backup_anchor_node_id
        return self.context_series
    

    def detection_run(self, state="PATCH"):
        """
        使用 cve_id + 项目 + commit + sink_nodeid 作为唯一标识符来缓存
        """
        STORAGE_PATH = "./detection_storage"
        backward_call_paths_file = os.path.join(STORAGE_PATH, 'source_finder', str(self.vuln_type), f'all_paths_{self.anchor_node.node_id}.pkl')
        potential_source_funcname_file = os.path.join(STORAGE_PATH, 'source_finder', str(self.vuln_type), f'all_potential_source_funcname_{self.anchor_node.node_id}.pkl')
        builtin_source_file = os.path.join(STORAGE_PATH, 'source_finder', str(self.vuln_type), f'all_builtin_source_{self.anchor_node.node_id}.pkl')
        def load_all_paths():
            try:
                with open(backward_call_paths_file, 'rb') as f:
                    self.backward_call_paths = pickle.load(f)

                with open(potential_source_funcname_file, 'rb') as f:
                    self.potential_source_funcname = pickle.load(f)

                with open(builtin_source_file, 'rb') as f:
                    self.sources = set(pickle.load(f))
                
                print(f"[+] Load existing paths and potential source function names for CVE {self.cve_id}, commit {self.commit_id}.")
                return True
            except FileNotFoundError:
                return False
        if load_all_paths():
            self.print_call_paths(self.backward_call_paths)
            self.print_potential_source_funcname()
            self.print_builtin_sources()
            if self.anchor_node_ast is None:
                self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
                return self.get_method_call_name(self.anchor_node_ast)
            else:
                return ""

        self.do_backward_slice()        # 收集调用 callsite


        for node_hash in self.__cache_center.already_detect_functions.keys():
            node_id, func_name = node_hash.split("::", 1)
            node_id = int(node_id)
            node = self.analyzer.get_node_itself(node_id)
            func_args_str = self.find_function_arg_node_list_1127(node)
            func_signature = func_name + func_args_str
            self.potential_source_funcname.add(func_signature)

        os.makedirs(os.path.join(STORAGE_PATH, 'source_finder', str(self.vuln_type)), exist_ok=True)
        with open(backward_call_paths_file, 'wb') as f:
            pickle.dump(self.backward_call_paths, f)

        with open(potential_source_funcname_file, 'wb') as f:
            pickle.dump(self.potential_source_funcname, f)

        with open(builtin_source_file, 'wb') as f:
            pickle.dump(self.sources, f)

        if self.anchor_node_ast is None:
            self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
        return self.get_method_call_name(self.anchor_node_ast)


    def testdata_detection_run(self):
        """
        使用 cve_id + 项目 + commit + sink_nodeid 作为唯一标识符来缓存
        """
        STORAGE_PATH = "./testdata_storage"
        backward_call_paths_file = os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), self.cve_id, f'all_paths_{self.anchor_node.node_id}.pkl')
        potential_source_funcname_file = os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), self.cve_id, f'all_potential_source_funcname_{self.anchor_node.node_id}.pkl')
        builtin_source_file = os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), self.cve_id, f'all_builtin_source_{self.anchor_node.node_id}.pkl')
        def load_all_paths():
            try:
                with open(backward_call_paths_file, 'rb') as f:
                    self.backward_call_paths = pickle.load(f)

                with open(potential_source_funcname_file, 'rb') as f:
                    self.potential_source_funcname = pickle.load(f)

                with open(builtin_source_file, 'rb') as f:
                    self.sources = set(pickle.load(f))
                
                print(f"[+] Load existing paths and potential source function names for CVE {self.cve_id}, commit {self.commit_id}.")
                return True
            except FileNotFoundError:
                return False
        self.context_series = ""
        if load_all_paths():
            self.print_call_paths(self.backward_call_paths)
            self.print_potential_source_funcname()
            self.print_builtin_sources()
            if self.anchor_node_ast is None:
                self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
                return self.get_method_call_name(self.anchor_node_ast)
            else:
                return ""

        self.do_backward_slice()        # 收集调用 callsite

        for node_hash in self.__cache_center.already_detect_functions.keys():
            node_id, func_name = node_hash.split("::", 1)
            node_id = int(node_id)
            node = self.analyzer.get_node_itself(node_id)
            func_args_str = self.find_function_arg_node_list_1127(node)
            func_signature = func_name + func_args_str
            self.potential_source_funcname.add(func_signature)

        os.makedirs(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type)), exist_ok=True)
        os.makedirs(os.path.join(STORAGE_PATH, 'cve_source_finder', str(self.vuln_type), self.cve_id), exist_ok=True)
        with open(backward_call_paths_file, 'wb') as f:
            pickle.dump(self.backward_call_paths, f)

        with open(potential_source_funcname_file, 'wb') as f:
            pickle.dump(self.potential_source_funcname, f)

        with open(builtin_source_file, 'wb') as f:
            pickle.dump(self.sources, f)

        if self.anchor_node_ast is None:
            self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
        return self.get_method_call_name(self.anchor_node_ast)


    # def do_backward_slice(self):
    #     self.__backup_anchor_node_id = self.anchor_node.node_id

    #     taint_param = set()
    #     if self.anchor_node_ast is None:
    #         self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
    #     if self.anchor_node_root is None:
    #         self.anchor_node_root = self.analyzer.ast_step.get_root_node(self.anchor_node_ast)
    #     self._do_backward_slice(self.anchor_node_ast, pdg_parent=None, id_threshold=self.anchor_node_ast[NODE_INDEX],
    #                             taint_param=taint_param)
    #     self.far_node = min(self.pdg_digraph.nodes.keys())  # 最远的有数据流关系的 node
    #     self.taint_param = taint_param

    def do_backward_slice(self):
        """启动过程间backward slice分析"""
        # self.__backup_anchor_node_id = self.anchor_node.node_id
        taint_param = None
        taint_param_pos = -1
        if self.anchor_node_ast is None:
            self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
        
        
        # rule1  第一个参数是常量的不用切片了，基本上都是无害的
        arg1_constant = self.analyzer.ast_step.check_first_arg_constant(self.anchor_node_ast)
        if arg1_constant:
            print(f"[-] Skip backward slice for node {self.anchor_node_ast[NODE_INDEX]} as first argument is constant.")
            return

        if self.anchor_node_root is None:
            self.anchor_node_root = self.analyzer.ast_step.get_root_node(self.anchor_node_ast)

        self._push_backward_call_stack(
            self.anchor_node_ast, 
            self.anchor_node_root, 
            "PATCH", 
            taint_param, 
            taint_param_pos,
            depth=0
        )
        
        # 获取 anchor 所在函数
        # self.sink_func_node = self.analyzer.basic_step.get_node_itself(
        #     self.anchor_node_ast[NODE_FUNCID]
        # )
        
        # 从 patch 开始backward slice，初始depth=0, level=0，因从从 sink backward 的不一定经过 patch
        self._do_backward_slice_interprocedural(
            self.anchor_node_ast, 
            pdg_parent=None, 
            id_threshold=self.anchor_node_ast[NODE_INDEX],
            taint_param=taint_param,
            depth=0,  # callee方向深度
            level=0   # caller方向层级
        )
        
        self.far_node = min(self.pdg_digraph.nodes.keys()) if self.pdg_digraph.nodes else None
        self.taint_param = taint_param

        self._pop_backward_call_stack()
        
        # 打印收集到的callsite信息
        self._print_backward_analysis_results()

        self.backward_call_stack.clear()
        self.anchor_node_ast = None
        self.anchor_node_root = None

    def _do_backward_slice_interprocedural(self, node, pdg_parent=None, id_threshold=0xff, taint_param=None,
                                    depth=0, level=0):
        """
        过程间backward slice核心函数
        
        Args:
            node: 当前分析的节点
            pdg_parent: PDG父节点（数据流的后继节点）
            id_threshold: 节点索引阈值（用于限制向前回溯的范围）
            taint_param: 污点参数集合
            depth: callee方向深度（分析被调用函数内部）
            level: caller方向层级（向上追踪到调用者）
        """
        if node is None:
            return
        
        # 深度限制检查
        if depth > self.max_callee_direction_depth:
            self._record_backward_path()
            return
        
        # if node[NODE_INDEX] > id_threshold:
        #     return
        
        # 标准化节点（确保有CFG）
        if not self.analyzer.cfg_step.has_cfg(node):
            node = self.analyzer.ast_step.get_root_node(node)
            if node[NODE_TYPE] in {TYPE_IF, TYPE_IF_ELEM, TYPE_WHILE, TYPE_DO_WHILE}:
                node = self.analyzer.get_control_node_condition(node)
        
        # 添加到PDG图
        self.pdg_digraph.add_node(
            node[NODE_INDEX], 
            add_rels="PDG", 
            root_node_id=node[NODE_INDEX], 
            lineno=node[NODE_LINENO],
        )
        
        # TODO: 检查是否找到source  这个地方也要再精进下，确保找到的是当前污点变量对应的 source
        global_vars = self.analyzer.ast_step.find_sources(node)
        if global_vars:
            self.sources.add(node[NODE_INDEX])
            add_source_count = 0
            for gvar in global_vars:
                if gvar[NODE_TYPE] == TYPE_DIM:
                    self._push_backward_call_stack(gvar, gvar, "SOURCE", "SOURCE", -1, depth)
                    add_source_count += 1
            self._record_backward_path()  # 找到source，记录路径
            for i in range(add_source_count):
                self._pop_backward_call_stack()
            return  # 找到source后可以停止当前分支的回溯
        
        # 添加PDG边
        if pdg_parent is not None:
            if taint_param is None:
                taint_param = None
            if not self.pdg_digraph.has_edge(node[NODE_INDEX], pdg_parent[NODE_INDEX]):
                self.pdg_digraph.add_edge(
                    node[NODE_INDEX], pdg_parent[NODE_INDEX], 
                    add_rels='PDG', 
                    taint_param=taint_param
                )
            else:
                return  # 已经处理过这条边，避免循环
        
        # 处理call节点 - 向callee方向分析
        # if node[NODE_TYPE] in {TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
        #     self._handle_backward_call_node(node, taint_param, depth, level, id_threshold)
        calleesite_nodes = self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES)
        if calleesite_nodes:
            for calleesite_node in calleesite_nodes:
                # 避免再进入到当前函数
                if calleesite_node[NODE_INDEX] in [self.anchor_node.node_id, node[NODE_INDEX]]:
                    continue
                self._handle_backward_call_node(calleesite_node, taint_param=taint_param, depth=depth, level=level+1)
        
        # 找到所有定义当前节点使用的变量的节点
        def_nodes = self.analyzer.pdg_step.find_def_nodes(node)
        if node in def_nodes:
            def_nodes.remove(node)
        
        # 检查数据流是否来自函数参数
        param_nodes = self._check_data_from_params(node, def_nodes, taint_param)
        
        # 如果数据来自参数且未达到caller层级限制，找 callee 的时候不向上了         # 向caller方向追踪
        if param_nodes and level < self.max_caller_direction_level:  
            taint_param = param_nodes[0]['taint_var']
            self._analyze_caller_functions(node, param_nodes, taint_param, depth, level)
        
        # 继续在当前函数内backward slice
        for def_node in def_nodes:
            if def_node is None or def_node[NODE_INDEX] > id_threshold:
                continue
            # if 'taint_var' in def_node:
            #     def_node_var_name = "$" + def_node['taint_var']
            #     if taint_param:
            #         if def_node_var_name != taint_param:
            #             continue

            # 获取污点变量
            var_rels = self.analyzer.neo4j_graph.relationships.match(
                [def_node, node], r_type=DATA_FLOW_EDGE
            )
            # current_taint = set(taint_param) if taint_param else set()
            
            for rel in var_rels:
                if 'var' in rel:
                    current_taint = '$' + rel['var']
            # current_taint = var_rels[0]['var']
            
            # 递归backward slice
            self._do_backward_slice_interprocedural(
                def_node, 
                pdg_parent=node, 
                id_threshold=def_node[NODE_INDEX],
                taint_param=current_taint,
                depth=depth,
                level=level
            )

    def get_method_call_name(self, node: py2neo.Node) -> str:

        def get_method_var_call_name(node: py2neo.Node) -> str:
            # 处理 $this->method() 这种形式 
            method_var_node = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_VAR})
            if method_var_node:
                method_var_node = method_var_node[0]
                method_var_name_nodes = self.analyzer.filter_ast_child_nodes(method_var_node, node_type_filter={TYPE_STRING})
                method_var_name_nodes = list(sorted(method_var_name_nodes, key=lambda x: x[NODE_INDEX]))
                method_name = ""
                if method_var_name_nodes:
                    method_name += "$"   
                    method_name += "->".join([n['code'] for n in method_var_name_nodes])
                method_name_node = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                if method_name_node:
                    method_name_node = method_name_node[0]
                    method_name += "->" + method_name_node['code']
                return method_name
            return None


        method_call_name = None
        node_type = node[NODE_TYPE]
        match node_type:
            case 'AST_METHOD_CALL':
                prop_node = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_PROP})
                if prop_node:
                    prop_node = prop_node[0]
                    prop_str_nodes = self.analyzer.filter_ast_child_nodes(prop_node, node_type_filter={TYPE_STRING})
                    prop_str_nodes = list(sorted(prop_str_nodes, key=lambda x: x[NODE_INDEX]))
                    prop_name = "$"
                    if prop_str_nodes:
                        prop_name += "->".join([n['code'] for n in prop_str_nodes]) 
                    method_name_nodes = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                    if method_name_nodes:
                        method_name_node = method_name_nodes[0]
                        prop_name += "->" + method_name_node['code']
                    method_call_name = prop_name
                else:
                    # 处理 var call
                    method_call_name = get_method_var_call_name(node)
                    if method_call_name is None:
                        method_submethod_node = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_METHOD_CALL})
                        if method_submethod_node:
                            parent_method_node = method_submethod_node[0]
                            parent_method_name = get_method_var_call_name(parent_method_node)

                            if parent_method_name is not None:
                                method_name_nodes = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                                if method_name_nodes:
                                    method_name_node = method_name_nodes[0]
                                    parent_method_name += "()->" + method_name_node['code']
                                    method_call_name = parent_method_name


                if method_call_name is None:
                    # 还有一种形式：
                    # $this->di['db']->getCell($sql , $values);   还有这种：$di['request']->getClientAddress(), 先不处理了吧。。
                    dim_node = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_DIM})
                    dim_node_method_call_name = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                    try:
                        if dim_node:
                            dim_node = dim_node[0]
                            dim_name_nodes = self.analyzer.find_ast_child_nodes(dim_node, include_type={TYPE_STRING})
                            dim_prop_node = self.analyzer.find_ast_child_nodes(dim_node, include_type={TYPE_PROP})
                            if dim_prop_node:
                                method_name = "$"
                                dim_prop_node = dim_prop_node[0]
                                dim_prop_var_node = self.analyzer.find_ast_child_nodes(dim_prop_node, include_type={TYPE_VAR})
                                dim_prop_var_name_node = self.analyzer.find_ast_child_nodes(dim_prop_var_node[0], include_type={TYPE_STRING})

                                if dim_prop_var_name_node:
                                    method_name += dim_prop_var_name_node[0]['code']

                                dim_prop_name_node = self.analyzer.find_ast_child_nodes(dim_prop_node, include_type={TYPE_STRING})
                                if dim_prop_name_node:
                                    method_name += "->" + dim_prop_name_node[0]['code']
                                    method_name += "['" + dim_name_nodes[0]['code'] + "']" 
                                    method_name += "->" + dim_node_method_call_name[0]['code']
                                    method_call_name = method_name
                    except Exception as e:
                        method_call_name = None
                        pass

                if method_call_name is None:
                    # 兜底，直接用 code
                    method_call_name = self.analyzer.code_step.get_node_code(node)

            case 'AST_STATIC_CALL':
                name_node = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_NAME})
                if name_node:
                    name_node = name_node[0]
                    static_name_node = self.analyzer.find_ast_child_nodes(name_node, include_type={TYPE_STRING})
                    static_name = ""
                    if static_name_node:
                        static_name_node = static_name_node[0]
                        static_name += static_name_node['code']
                    static_method_name = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                    if static_method_name:
                        static_method_name = static_method_name[0]
                        static_name += "::" + static_method_name['code']
                    method_call_name = static_name
    
        if method_call_name is None:
            # 兜底，直接用 code
            method_call_name = self.analyzer.code_step.get_node_code(node)
        return method_call_name

    # TODO: 应该再加个字段，表明是否实际进入了被调用函数  还是只是记录一个函数名
    def _handle_backward_call_node(self, call_node, taint_param, depth, level):
        """
        处理backward分析中遇到的call节点
        向callee方向分析：数据流可能来自被调用函数的返回值
        """
        # 收集callsite
        # 这里要考虑method name 和 funcname
        call_node_name = None
        if call_node[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
            call_node_name = self.get_method_call_name(call_node)
        else:
            call_node_name = self.analyzer.code_step.get_node_code(call_node)

        callsite_info = {
            'node': call_node,
            'node_id': call_node[NODE_INDEX],
            'code': call_node_name,
            'location': self._get_node_location(call_node),
            'direction': 'callee',
            'depth': depth,
            'level': level
        }

        for callsite in self.backward_call_stack:
            if callsite['direction'] == 'callee':
                if callsite_info['code'] == callsite['call_site_code'] and callsite_info['code'] == callsite['callee_name']:
                    return
            elif callsite['direction'] == 'caller':
                if callsite_info['code'] == callsite['call_site_code'] and callsite_info['code'] == callsite['caller_name']:
                    return

        self.collected_backward_callsites.append(callsite_info)
        
        # 找到被调用函数的声明  找不到也要加入 processed 集合，找不到实现但是也调用了。只不过没有更深的 call chain. 不仅要加入processed 还要 push 到栈中啊
        func_decls = self.analyzer.cg_step.find_decl_nodes(call_node)
        args_list = self.analyzer.ast_step.find_function_arg_node_list(call_node)
        args_pos = args_list.get(taint_param, -1)
        if not func_decls:
            call_hash = f"{call_node[NODE_INDEX]}_0"
            if call_hash in self.already_processed_backward_callsite:
                return
            self.already_processed_backward_callsite.add(call_hash)
            node_hash = f"{call_node[NODE_INDEX]}::{call_node_name}"
            self.__cache_center.update_already_detect_functions(node_hash, 1)
            self._push_backward_call_stack(
                call_node, call_node, "return_value", taint_param, args_pos, depth
            )
            self._record_backward_path()
            self._pop_backward_call_stack()
            return
        
        func_decl = func_decls[-1]
        
        # 避免重复分析
        call_hash = f"{call_node[NODE_INDEX]}_{func_decl[NODE_INDEX]}"
        if call_hash in self.already_processed_backward_callsite:
            return
        self.already_processed_backward_callsite.add(call_hash)

        
        func_name = call_node_name
        if func_name == "build_graph_object_sql_having":
            print("db")
        node_hash = f"{func_decl[NODE_INDEX]}::{func_name}"
        self.__cache_center.update_already_detect_functions(node_hash, 1)
        
        # 压入调用栈
        self._push_backward_call_stack(
            call_node, func_decl, "return_value", taint_param, args_pos, depth
        )
        
        # 分析被调用函数的return语句
        depth += 1
        if depth <= self.max_callee_direction_depth:
            self._analyze_callee_returns(func_decl, call_node, taint_param, depth, level)
        else:
            self._record_backward_path()
        # 弹出调用栈
        self._pop_backward_call_stack()


    def _analyze_callee_returns(self, func_decl, call_node, taint_param, depth, level):
        """
        分析被调用函数的return语句
        如果return语句返回的值依赖某些变量，继续在函数内backward slice
        """
        # 找到所有return语句
        return_nodes = self.analyzer.ast_step.filter_child_nodes(
            func_decl, node_type_filter=[TYPE_RETURN]
        )
        
        for return_node in return_nodes:
            # 获取return语句的根节点
            return_root = self.analyzer.ast_step.get_root_node(return_node)
            
            # 从return节点开始backward slice
            # 设置id_threshold为return节点的index，限制只分析函数内部
            func_start_index = func_decl[NODE_INDEX]
            
            self._do_backward_slice_interprocedural(
                return_root,
                pdg_parent=None,
                id_threshold=return_root[NODE_INDEX],
                taint_param=taint_param,
                depth=depth,
                level=level
            )


    def _check_data_from_params(self, node, def_nodes, taint_param):
        """
        检查数据流是否来自函数参数
        返回污点参数节点列表
        """
        param_nodes = []
        
        for def_node in def_nodes:
            if def_node[NODE_TYPE] == TYPE_PARAM:
                param_nodes.append(def_node)
        
        return param_nodes


    def _analyze_caller_functions(self, param_use_node, param_nodes, taint_param, depth, level):
        """
        向caller方向分析：当数据来自参数时，追踪到调用者
        TODO: 增加记录重复调用的功能，如果已经分析过则不要再次分析。根据函数名来
        Args:
            param_use_node: 使用参数的节点
            param_nodes: 参数节点列表
            taint_param: 当前污点参数集合
            depth: 当前callee深度
            level: 当前caller层级
        """
        if level >= self.max_caller_direction_level:  # caller层级限制
            self._record_backward_path()
            return
        
        # 获取当前函数
        current_func = self.analyzer.basic_step.get_node_itself(
            param_use_node[NODE_FUNCID]
        )
        
        if current_func is None:
            return
        
        # 找到所有调用当前函数的call site
        call_sites = self.analyzer.cg_step.find_call_nodes(current_func)
        
        if not call_sites:
            self._record_backward_path()
            return
        
        if len(call_sites) > 5:  # 限制调用点数量，避免路径爆炸
            call_sites = call_sites[:3]
        
        for param_node in param_nodes:
            param_position = param_node[NODE_CHILDNUM]  # 参数位置
            
            for call_site in call_sites:
                # 避免重复处理
                call_hash = f"{call_site[NODE_INDEX]}_{current_func[NODE_INDEX]}"
                if call_hash in self.already_processed_backward_callsite:
                    continue
                self.already_processed_backward_callsite.add(call_hash)
                
                if call_site[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
                    call_site_name = self.get_method_call_name(call_site)
                else:
                    call_site_name = self.analyzer.code_step.get_node_code(call_site)

                # 收集callsite信息
                callsite_info = {
                    'node': call_site,
                    'node_id': call_site[NODE_INDEX],
                    'code': call_site_name,
                    'location': self._get_node_location(call_site),
                    'direction': 'caller',
                    'depth': depth,
                    'level': level,
                    'param_position': param_position
                }
                self.collected_backward_callsites.append(callsite_info)
                
                # 获取caller函数
                caller_func = self.analyzer.basic_step.get_node_itself(
                    call_site[NODE_FUNCID]
                )
                
                # TODO: 找到call site对应位置的参数  这个部分的 arg list 还是要再精进下
                taint_arg = None
                args_list = self.analyzer.ast_step.find_function_arg_node_list(call_site)
                for arg_name, arg_pos in args_list.items():
                    if arg_pos == param_position:
                        taint_arg = arg_name
                        break

                matching_arg_node = None
                # 这部分处理的没问题，但是会影响后面的逻辑，暂时就直接用 callsite
                # for arg_name, arg_pos in args_list.items():
                #     if arg_pos == param_position:
                #         # 找到对应参数的AST节点
                #         arg_nodes = self.analyzer.ast_step.filter_child_nodes(
                #             call_site, node_type_filter=VAR_TYPES_EXCLUDE_CONST_VAR
                #         )
                #         for arg_node in arg_nodes:
                #             if arg_node[NODE_CHILDNUM] == param_position:
                #                 matching_arg_node = arg_node
                #                 break
                #         break
                # 实际上找的就是 taint var 参数在 caller 中的数据流向，这里处理的没错
                if matching_arg_node is None:
                    # 如果没找到具体的参数节点，使用call_site的根节点
                    matching_arg_node = self.analyzer.ast_step.get_root_node(call_site)
                
                # 压入caller栈
                self._push_backward_caller_stack(
                    call_site, caller_func, param_node, taint_param, param_position, level
                )
                
                # 在caller函数中继续backward slice
                new_level = level + 1   # 这里移动到上面
                # call_site_root = self.analyzer.ast_step.get_root_node(call_site)
                
                self._do_backward_slice_interprocedural(
                    matching_arg_node,
                    pdg_parent=None,
                    id_threshold=matching_arg_node[NODE_INDEX],
                    taint_param=taint_arg,
                    depth=0,  # 重置depth，因为进入了新的caller函数
                    level=new_level
                )
                
                # 弹出caller栈
                self._pop_backward_caller_stack() 


    # ===== 调用栈管理函数 =====

    def _push_backward_call_stack(self, call_site, callee_func, marker, taint_param, param_pos, depth):
        """压入backward callee调用栈"""
        call_info = {
            'call_site': call_site,
            'call_site_code': self.get_method_call_name(call_site) if call_site[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL} else self.analyzer.code_step.get_node_code(call_site),
            'callee': callee_func,
            'callee_name': self.get_method_call_name(call_site) if callee_func[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL} else self.analyzer.code_step.get_node_code(call_site),
            'marker': marker,
            'taint_param': taint_param,
            'param_pos': param_pos,
            'depth': depth,
            'direction': 'callee',
            'location': self._get_node_location(call_site),
            'funcid': call_site[NODE_FUNCID]
        }
        self.backward_call_stack.append(call_info)


    def _push_backward_caller_stack(self, call_site, caller_func, param_node, taint_param, param_pos,level):
        """压入backward caller调用栈"""
        call_info = {
            'call_site': call_site,
            'call_site_code': self.get_method_call_name(call_site) if call_site[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL} else self.analyzer.code_step.get_node_code(call_site),
            'caller': caller_func,
            'caller_name': self.get_method_call_name(caller_func) if caller_func[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL} else self.analyzer.code_step.get_node_code(caller_func),
            'param_node': param_node,
            'param_name': self.get_method_call_name(param_node) if param_node[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL} else self.analyzer.code_step.get_node_code(param_node),
            'taint_param': taint_param,
            'param_pos': param_pos,
            'level': level,
            'direction': 'caller',
            'location': self._get_node_location(call_site),
            'funcid': call_site[NODE_FUNCID]
        }
        self.backward_call_stack.append(call_info)


    def _pop_backward_call_stack(self):
        """弹出backward调用栈"""
        if self.backward_call_stack:
            self.backward_call_stack.pop()


    def _pop_backward_caller_stack(self):
        """弹出backward caller栈"""
        if self.backward_call_stack:
            self.backward_call_stack.pop()


    def _record_backward_path(self):
        """记录当前完整的backward调用路径"""
        if not self.backward_call_stack:
            return
        
        path = []
        for call_info in self.backward_call_stack:
            path_entry = {
                'call_site_nodeid': call_info['call_site'][NODE_INDEX],
                'call_site_code': call_info['call_site_code'],
                'direction': call_info['direction'],
                'location': call_info['location'],
                'param_pos': call_info.get('param_pos', -1),
                'funcid': call_info['funcid']
            }
            
            if call_info['direction'] == 'callee':
                path_entry['callee_name'] = call_info['callee_name']
                path_entry['depth'] = call_info['depth']
            else:  # caller
                path_entry['caller_name'] = call_info['caller_name']
                path_entry['param_name'] = call_info['param_name']
                path_entry['level'] = call_info['level']

            if "marker" in call_info and call_info["marker"] in {"SOURCE", "SINK"}:
                path_entry['marker'] = call_info["marker"]
            path.append(path_entry)
        
        # 避免重复路径  
        if not self._is_duplicate_backward_path(path):
            self.backward_call_paths.append(path)


    def _is_duplicate_backward_path(self, new_path):
        """检查是否为重复的backward路径"""
        for existing_path in self.backward_call_paths:
            if len(existing_path) != len(new_path):
                continue
            
            is_same = True
            for i, entry in enumerate(new_path):
                if entry['location'] != existing_path[i]['location'] or entry['call_site_code'] != existing_path[i]['call_site_code']:
                    is_same = False
                    break
            
            if is_same:
                return True
        
        return False


    def _get_node_location(self, node):
        """获取节点的位置信息"""
        file_name = self.analyzer.fig_step.get_belong_file(node)
        
        return {
            'file': file_name,
            'line': node[NODE_LINENO] if NODE_LINENO in node else 'unknown'
        }


    def _print_backward_analysis_results(self):
        """打印backward分析结果"""
        print("\n" + "="*80)
        print("Backward Slice Analysis Results")
        print("="*80)
        
        print(f"\n[*] Total collected callsites: {len(self.collected_backward_callsites)}")
        print(f"[*] Total backward paths: {len(self.backward_call_paths)}")
        print(f"[*] Sources found: {len(self.sources)}")
        
        # 按方向分组统计
        callee_callsites = [c for c in self.collected_backward_callsites if c['direction'] == 'callee']
        caller_callsites = [c for c in self.collected_backward_callsites if c['direction'] == 'caller']
        
        print(f"\n[*] Callee direction callsites: {len(callee_callsites)}")
        print(f"[*] Caller direction callsites: {len(caller_callsites)}")
        
        # 打印callsite详情
        print("\n" + "-"*80)
        print("Collected Callsites:")
        print("-"*80)
        
        for i, callsite in enumerate(self.collected_backward_callsites, 0):
            print(f"\n[{i}] {callsite['direction'].upper()} direction (depth={callsite['depth']}, level={callsite['level']})")
            print(f"    Code: {callsite['code']}")
            print(f"    Location: {callsite['location']['file']}:{callsite['location']['line']}")
            if 'param_position' in callsite:
                print(f"    Parameter position: {callsite['param_position']}")
        
        # 打印路径信息
        if self.backward_call_paths:
            print("\n" + "-"*80)
            print("Backward Call Paths:")
            print("-"*80)
            
            for i, path in enumerate(self.backward_call_paths, 0):
                print(f"\n[Path {i}] Length: {len(path)}")
                for j, step in enumerate(path):
                    indent = "  " * j
                    print(f"{indent}→ {step['direction']}: {step['call_site_code']}")
                    print(f"{indent}  @ {step['location']['file']}:{step['location']['line']}")
                    print(f"{indent}  * Position: {step.get('param_pos', 'N/A')}")
                    if 'marker' in step:
                        print(f"{indent}  * Marker: {step['marker']}")
        print("\n" + "="*80)
    
    # 这里也可以优化一下试试，直接用图，不用查询交互（但是估计不会快太多，但是要试一下） 可以改造的，find source 不过就是向下查询x层子节点，可以手搓个遍历，而且这个 slice 比切片还简单，因为只 slice 数据流
    # def _do_backward_slice(self, node, pdg_parent=None, id_threshold=0xff, taint_param: set = None):
    #     if node is None:
    #         return None
    #     if node[NODE_INDEX] > id_threshold:
    #         return None
        
    #     if not self.analyzer.cfg_step.has_cfg(node):
    #         node = self.analyzer.ast_step.get_root_node(node)
    #         if node[NODE_TYPE] in {TYPE_IF, TYPE_IF_ELEM, TYPE_WHILE, TYPE_DO_WHILE}:
    #             node = self.analyzer.get_control_node_condition(node)

    #     self.pdg_digraph.add_node(
    #             node[NODE_INDEX], add_rels="PDG", root_node_id=node[NODE_INDEX], lineno=node[NODE_LINENO],
    #     )
    #     if self.analyzer.ast_step.find_sources(node):
    #         self.sources.add(node[NODE_INDEX])  # 这里保存的是 node，find_source 是找的其child，例如node 是 assign，那保存的就是这个 assign 语句
        
    #     if pdg_parent is not None:
    #         assert taint_param is not None
    #         if self.pdg_digraph.has_edge(node[NODE_INDEX], pdg_parent[NODE_INDEX]):
    #             return
    #         else:
    #             self.pdg_digraph.add_edge(
    #                 node[NODE_INDEX], pdg_parent[NODE_INDEX], add_rels='PDG', taint_param=taint_param
    #             )
        
    #     # 所有能到达当前 node 的变量定义
    #     def_nodes = self.analyzer.pdg_step.find_def_nodes(node)
    #     if node in def_nodes:
    #         def_nodes.pop(def_nodes.index(node))
        
    #     for def_node in def_nodes:
    #         if def_node is None or def_node[NODE_INDEX] > id_threshold: continue
    #         var = self.analyzer.neo4j_graph.relationships.match([def_node, node],
    #                                                             r_type=DATA_FLOW_EDGE).first()['var']
    #         taint_param.add('$' + var)
    #         self._do_backward_slice(def_node, pdg_parent=node, id_threshold=def_node[NODE_INDEX], 
    #                             taint_param=taint_param)

    # add: 添加了对自定义 source 的支持
    def do_forward_path_exploration(self):
        potential_condition_nodes = [i for i, in self.analyzer.run(
            "MATCH (A:AST) - [:PARENT_OF] -> (B:AST) WHERE A.type='AST_IF_ELEM' AND B.childnum=0 " + \
            f"AND B.type <> 'NULL' AND {self.far_node - 100} <= B.id AND B.id <= {self.far_node} RETURN B"
        )]      # 这里限制 far 的目的是要找到最早污点之前的 check，相当于初始化一个，并不是全部的 check 都要找，因为后续的遍历不会遍历 far_node 之前，只会遍历 far_node 到 sink_node 之间的节点
        condition_ids = set()
        for node in potential_condition_nodes:
            parent_node = self.analyzer.get_ast_parent_node(node)
            low_bound, high_bound = self.analyzer.range_step.get_condition_range(parent_node)
            if low_bound <= self.far_node and self.far_node <= high_bound and \
                    (self.analyzer.ast_step.find_sources(node) or self.analyzer.ast_step.find_custom_sources(node, self.custom_sources)):  # 找到 check 范围内的 global var，只有当 condition 里有 global 时才添加到 condition_ids，即这个 check 才有意义
                condition_ids.add(node[NODE_INDEX])
        
        far_node_ast = self.analyzer.get_node_itself(self.far_node)

        if self.anchor_node_root[NODE_INDEX] == far_node_ast[NODE_INDEX]:
            self.context_series.append(([self.anchor_node.node_id], sorted(condition_ids)))
            return

        self._do_forward_path_exploration(node=far_node_ast, cfg_pdg_path=set(), path_conditions=condition_ids,  
                                          threshold=[far_node_ast[NODE_INDEX], self.anchor_node_ast[NODE_INDEX]],
                                          cycle_exit_identifier=set())  # range 控制在 far_node 之后 sink_node 之前

    def _do_forward_path_exploration(self, node: py2neo.Node, cfg_pdg_path: set = set(), path_conditions: set = set(),
                                     has_source=False, threshold=None, cycle_exit_identifier: set = None, **kwargs):
        # 没有 source 都是白扯
        # forward 策略需要更新？ 路径爆炸。。。

        if self.sources.__len__() == 0:
            return None
        
        if cycle_exit_identifier is None:
            cycle_exit_identifier = {(-0xcaff, -0xcaff)}
        if threshold is None:
            threshold = [-0xff, 0xffff]
        threshold_bottom, threshold_upper = threshold
        # 从 farnode 开始 farward exploration
        if node is None or node.labels.__str__() != ":" + LABEL_AST:
            return None
        if node[NODE_INDEX] < threshold_bottom or node[NODE_INDEX] > threshold_upper:
            return None
        # 找到循环出口点，讲 node 替换为出口点的后继节点，那这样，循环体内不就不会被遍历吗？
        node = self._find_outside_exit_identifier(cycle_exit_identifier, node)
        if node[NODE_LINENO] is None:
            return None

        if node[NODE_INDEX] in self.pdg_digraph.nodes.keys():   # 有数据关系直接加到 cfg_pdg_path 中来
            cfg_pdg_path.add(node[NODE_INDEX])
            if node[NODE_INDEX] in self.sources:
                has_source = True

        # 如果 前向遍历的 node 已经超过了 sink 点并且遍历到了sink点，那么 forward exploration 就结束了，添加数据流路径
        if node[NODE_INDEX] >= self.anchor_node_root[NODE_INDEX]:
            if self.anchor_node_root[NODE_INDEX] in cfg_pdg_path and \
                has_source:
                path_to_add = sorted(cfg_pdg_path)
                path_to_add[-1] = self.anchor_node_ast[NODE_INDEX]
                conditions_to_add = sorted(path_conditions)
                if (path_to_add, conditions_to_add) not in self.context_series:
                    self.context_series.append((path_to_add, conditions_to_add))
            return None

        parent_node = self.analyzer.ast_step.get_parent_node(node)
        if parent_node[NODE_TYPE] in {TYPE_WHILE}:  
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                # source_rels = [i for i, in self.analyzer.run(
                #     f"MATCH P = (S:AST) - [:REACHES*1..] -> (C:AST) WHERE S.id in {list(self.sources).__str__()} " + \
                #     f"AND C.id={node[NODE_INDEX]} RETURN P"
                # )]
                cypher = (
                    f"MATCH (S:AST), (C:AST {{id: {node[NODE_INDEX]}}}) "
                    f"WHERE S.id IN {list(self.sources)} "
                    f"MATCH P = shortestPath((S)-[:REACHES*1..]->(C)) "
                    f"RETURN P"
                )
                source_rels = [i for i, in self.analyzer.run(cypher)]
                if source_rels or self.analyzer.ast_step.find_sources(node) or self.analyzer.ast_step.find_custom_sources(node, self.custom_sources):
                    path_conditions.add(node[NODE_INDEX])
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[1].end_node))
                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper]) # cfg_rels[0] 是 true 分支，cfg_rels[0].end_node 是循环体内的第一个节点，所以这是进入循环体内继续遍历
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                # 这里 reaches*1.. 会非常慢，因此先判断 source，如果为空就不要浪费时间，然后使用 
                # MATCH (S:AST {id: 273}), (C:AST {id: 297})
                # MATCH P = shortestPath((S)-[:REACHES*1..]->(C))
                # RETURN P
                # shortestPath 来查询

                # source_rels = [i for i, in self.analyzer.run(
                #     f"MATCH P = (S:AST) - [:REACHES*1..] -> (C:AST) WHERE S.id in {list(self.sources).__str__()} " + \
                #     f"AND C.id={node[NODE_INDEX]} RETURN P"
                # )]  # 看 source 的 def 能否到达当前 condition node  这一步很浪费时间
                
                # MATCH (S:AST), (C:AST {id: 297})
                # where S.id in [128, 191, 226, 353, 164, 264, 137, 173, 209, 146, 437, 182, 217, 155, 255]
                # MATCH P = shortestPath((S)-[:REACHES*1..]->(C))
                # RETURN P
                cypher = (
                    f"MATCH (S:AST), (C:AST {{id: {node[NODE_INDEX]}}}) "
                    f"WHERE S.id IN {list(self.sources)} "
                    f"MATCH P = shortestPath((S)-[:REACHES*1..]->(C)) "
                    f"RETURN P"
                )
                source_rels = [i for i, in self.analyzer.run(cypher)]
                
                if source_rels or self.analyzer.ast_step.find_sources(node) or self.analyzer.ast_step.find_custom_sources(node, self.custom_sources):
                    path_conditions.add(node[NODE_INDEX])
                cfg_rel_true, cfg_rel_false = cfg_rels
                self._do_forward_path_exploration(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cfg_pdg_path=cfg_pdg_path, cycle_exit_identifier=cycle_exit_identifier,
                        path_conditions=path_conditions, has_source=has_source,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_true['flowLabel']},
                )
                if node[NODE_INDEX] in path_conditions:
                    path_conditions.remove(node[NODE_INDEX])
                self._do_forward_path_exploration(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cfg_pdg_path=cfg_pdg_path, cycle_exit_identifier=cycle_exit_identifier,
                        path_conditions=path_conditions, has_source=has_source,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_false['flowLabel']},
                )
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_FOR} and node[NODE_CHILDNUM] == 1:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add(
                        (self.analyzer.ast_step.get_ith_child_node(parent_node, i=2), cfg_rels[1].end_node))

                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif node[NODE_TYPE] in {TYPE_FOREACH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                if cfg_rels[0]['flowLabel'] == 'complete':
                    complete_index, next_index = 0, 1
                else:
                    complete_index, next_index = 1, 0
                cfg_rel = cfg_rels[next_index]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[complete_index].end_node))
                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_TRY}:
            pass
        elif parent_node[NODE_TYPE] in {TYPE_SWITCH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels[-1][CFG_EDGE_FLOW_LABEL] == 'default':
                cfg_rels[-1][
                    CFG_EDGE_FLOW_LABEL] = f"! ( in_array( {TMP_PARAM_FOR_SWITCH},{[i['flowLabel'] for i in cfg_rels[:-2]]}) )"
            for index in range(cfg_rels.__len__()):
                self._do_forward_path_exploration(node=cfg_rels[index].end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rels[index].start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper],
                                                  edge_property={"flowLabel": f"\'{cfg_rels[index]['flowLabel']}\'"})
        else:
            cfg_next_node = self.analyzer.cfg_step.find_successors(node)
            if cfg_next_node.__len__() == 0:
                return
            cfg_next_node = cfg_next_node[-1]
            if node[NODE_TYPE] in {TYPE_EXIT}:
                self._do_forward_path_exploration(node=cfg_next_node, cfg_pdg_path=cfg_pdg_path, 
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=None,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                self._do_forward_path_exploration(node=cfg_next_node, cfg_pdg_path=cfg_pdg_path, 
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
        if node[NODE_INDEX] in cfg_pdg_path:
            cfg_pdg_path.remove(node[NODE_INDEX])
        if node[NODE_INDEX] in path_conditions:
            path_conditions.remove(node[NODE_INDEX])

    def _find_outside_exit_identifier(self, cycle_exit_identifier, input_node):
        for _cycle_exit_identifier in cycle_exit_identifier:
            if input_node == _cycle_exit_identifier[0]:
                input_node = self._find_outside_exit_identifier(cycle_exit_identifier, _cycle_exit_identifier[1])
        return input_node
        

    # add: find more sources
    # 现在已经有了 taint_param，接下来需要找到这些 taint_param 的来源，参数的标记但不处理（跨过程）先处理来自当前函数内赋值的
    def do_find_extend_source(self):
        # 先获取 self.pdg_digraph 中所有节点
        potential_var_code_all = []
        taint_var_def_node_roots = set()
        for taint_param in self.taint_param:
            var_name = taint_param[1:]  
            potential_taint_var_nodes = [i for i, in self.analyzer.run(
                f"MATCH (n:AST) where n.code='{var_name}' return n"
            )]

            taint_var_nodes = set()
            for taint_var_node in potential_taint_var_nodes:
                parent_node = self.analyzer.ast_step.get_parent_node(taint_var_node)
                if parent_node[NODE_TYPE] in {TYPE_VAR}:
                    taint_var_nodes.add(parent_node)

            taint_var_nodes = list(sorted(taint_var_nodes, key=lambda x: x[NODE_INDEX], reverse=False))

            # 对所有是 var 来进行来源分析  (先处理函数调用赋值的，晚会再处理函数参数的)
            # TODO 这里需要像 mystique 一样合并 edge 这样 def 才能找的更准
            # 如果这个变量没有 def reach 则证明这个变量是个 def
            taint_var_def_nodes = set()
            for taint_var_node in taint_var_nodes:
                def_nodes = self.analyzer.pdg_step.find_def_nodes(taint_var_node)
                if def_nodes.__len__() == 0:
                    taint_var_def_nodes.add(taint_var_node)

            
            for taint_var_def_node in taint_var_def_nodes:
                taint_var_def_node_root = self.analyzer.ast_step.get_root_node(taint_var_def_node)
                taint_var_def_node_roots.add(taint_var_def_node_root)


        # 这里拿出来统一处理
        # 这里进行优化处理，如果有 ast_call 的就只保留一个 减少prompt 长度
        unique_taint_var_def_node_roots = set()
        unique_callsite_names = set()
        for taint_var_def_node_root in list(taint_var_def_node_roots):
            if taint_var_def_node_root[NODE_TYPE] == TYPE_CALL:
                # TODO 这里除了 type_call 还有其他类型的调用，然后对于name_child 可以使用更精确的方式获取 filter_child_nodes
                if NODE_CODE in self.analyzer.get_ast_child_node(self.analyzer.get_ast_child_node(taint_var_def_node_root)).keys():
                    callsite_name = self.analyzer.get_ast_child_node(self.analyzer.get_ast_child_node(taint_var_def_node_root))[NODE_CODE]
                    if callsite_name in unique_callsite_names:
                        continue
                    else:
                        unique_callsite_names.add(callsite_name)
                        unique_taint_var_def_node_roots.add(taint_var_def_node_root)
            else:
                unique_taint_var_def_node_roots.add(taint_var_def_node_root)



        var_def_codes = list()
        for taint_var_def_node_root in unique_taint_var_def_node_roots:
            code = Ast2CodeFactory.extract_code(self.analyzer, [taint_var_def_node_root], normalize_level=0)[0]
            var_def_codes.append(code)
        potential_var_code_all.extend(var_def_codes)
        # 得到 var_def_codes 之后，直接和LLM交互？找到 source，然后动态添加进source 中


        prompt_all_callsite = "\n".join(
            [f"callsite {index + 1}: {code}" for index, code in enumerate(potential_var_code_all)]
        )

        prompt = """
You are a code analysis expert. Analyze a given PHP function call and determine whether it **directly receives external input** (e.g., from HTTP requests, cookies, environment variables, CLI arguments, etc.). Focus purely on the function’s ability to **access or retrieve input from external sources** based on its name and parameter content. Do not consider sanitization or later usage.

Guidelines:

1. **Function semantics**:
   - Functions, superglobals, or methods whose names or arguments indicate **direct interaction with external sources** are candidates.

2. **Directness of input**:
   - The function or expression must be the **first point** where data enters the program from the external environment.
   - Wrapper functions that merely *pass along* data already retrieved should **not** be considered direct receivers.

3. **Parameter inspection**:
   - If parameters or arguments reference known external sources (superglobals or special input streams), the call should be considered as directly receiving input.

4. **Output format**:
   - Use a single XML tag containing a **list of function or source names** that directly receive external input.
   - Example: `<answer>[$_GET, getenv]</answer>`
   - If no function or source directly receives external input, output an empty list: `<answer>[]</answer>`

### Input
{call_expr}

### Output
<answer>[your answer]</answer>
"""
        prompt = prompt.format(call_expr=prompt_all_callsite)

        response = openai_chat(prompt, temperature=0.1)
        print("LLM Response:", response)
        # Extract the answer from the response
        if "<answer>" in response and "</answer>" in response:
            answer = response.split("<answer>")[1].split("</answer>")[0].strip()
            print("Extracted Answer:", answer)


        # 把 answer 解析成 list
        if answer.startswith("[") and answer.endswith("]"):
            items = answer[1:-1].split(",")
            for item in items:
                item = item.strip().strip("'").strip('"')
                if item:
                    self.custom_sources.add(item)
        print("Custom Sources List:", self.custom_sources)


        # 遍历 pdg_digraph，如果 node 的 code 在 custom_sources 中，则添加到 sources 中
        for node_id in self.pdg_digraph.nodes.keys():
            node = self.analyzer.get_node_itself(node_id)
            if self.analyzer.ast_step.find_custom_sources(node, self.custom_sources):
                self.sources.add(node_id)

        # 添加到 source 后，forward 的逻辑会变？因为这个 source 是个函数调用

        # 现在的问题是 backward_slice 太慢了，怎么解决下
        # 慢的原因是 find_source 层数太多了，把层数减少(暂时这么解决，后面想办法优化)

        # 我感觉这里也需要跨层遍历收集信息，或者是把之前收集的 callsite 信息用来