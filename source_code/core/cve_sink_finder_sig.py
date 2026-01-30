import json
import logging
import os.path
import pickle
from typing import Dict, List, Set, Tuple, Union

import py2neo
import copy
import sys
import networkx as nx
from abc import ABC, abstractmethod

from config.path import STORAGE_PATH
from core.anchor_node import AnchorNode
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.modified_line import ModifiedLine
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *

logger = logging.getLogger(__name__)

COMMON_NODE_TYPES = [
        TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL,
        TYPE_NEW,
        TYPE_INCLUDE_OR_EVAL,
        TYPE_ECHO, TYPE_PRINT, TYPE_EXIT
]

TRAVERSAL_REPORT_THRESHOLD = 2
CONFIG_TAINT_DYNAMIC_CALL_FLAG = True

FUNCTION_MODEL = {
        7: ["include", "require", "include_once", "require_once"],
        2: ["file", "file_get_contents", "readfile", "fopen"],
        1: ["unlink", "rmdir"],
        12: ["file_put_contents", "fopen", "fwrite"],
        10: ["echo", "print", "print_r", "die"],
        4: ["exec", "passthru", "proc_open", "system", "shell_exec", "popen", "pcntl_exec"],
        3: ["eval", 'create_function', 'assert', 'array_map', 'preg_replace'],
        6: ["copy", "fopen", "move_uploaded_file", "rename"],
        13: ["header", ],
        8: ["unserialize", ],
        9: ["pg_query", "pg_send_query", "pg_prepare", "mysql_query", "mysqli_prepare", "mysqli_query",
            "mysqli_real_query"]
}

class AnchorFinderConfigure(object):
    def __init__(self, level: Union[int, Dict] = None):
        default_level = 0
        if level is None:
            level = default_level
        self.__level = level
        # 这个的意思是：
        # 第一次尝试sink查找，向callee方向找1层，向caller方向找0层
        # 第二次尝试sink查找，向callee方向找2层，向caller方向找1层
        # 第三次尝试sink查找，向callee方向找3层，向caller方向找2层
        self.__default_config = {
                0: {'__callee_depth': 0b0010},
                1: {'__callee_depth': 0b0011},
                2: {'__callee_depth': 0b0100},
        }
        self.__max_level = max(self.__default_config.keys())
        if isinstance(level, int):
            assert level in self.__default_config.keys()
            self.__callee_depth = self.__default_config[level]['__callee_depth']
        elif isinstance(level, Dict):      
            self.__callee_depth = \
                level.pop('__callee_depth',
                          self.__default_config[default_level]['__callee_depth']) 

    @property
    def configure_level(self) -> int:
        return self.__level

    @property
    def configure_max_level(self) -> int:
        return self.__max_level

    @property
    def rule_callee_depth(self) -> int:
        return self.__callee_depth


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


class AcnhorNodeList(Set):
    def __init__(self):
        super(AcnhorNodeList, self).__init__()

    def add(self, __object, analyzer: Neo4jEngine) -> None:
        _obj_ast = analyzer.basic_step.get_node_itself(__object.node_id)
        if analyzer.pdg_step.is_tracable(_obj_ast=_obj_ast):
            super(AcnhorNodeList, self).add(__object)

    def add_without_check(self, __object: AnchorNode):
        super(AcnhorNodeList, self).add(__object)


class CalleeDepthType():
    def __init__(self, depth: int = 0):
        self.depth = depth


class CVESinkFinderSig(object):
    def __compile_anchor_functions(self, vuln_type: int, custom_sinks: List[str] = None):
        if isinstance(vuln_type, int) or (isinstance(vuln_type, str) and vuln_type.isdigit()):
            assert int(vuln_type) in FUNCTION_MODEL.keys(), f'[*] the vuln type id {vuln_type} not in list'
            self.anchor_functions = FUNCTION_MODEL[int(vuln_type)] + (custom_sinks if custom_sinks else [])
        else:
            raise NotImplementedError(f"error data type for vuln_type {type(vuln_type)}")
        
    def __complie_storage_path(self):
        storage_dir = os.path.join(STORAGE_PATH, "sink_finding_result")
        if not os.path.exists(storage_dir):
            os.mkdir(storage_dir)
        self.sink_storage_path = os.path.join(storage_dir, f"{self.cve_id}_{self.patch_commit_id}.json")

    def __init__(self, analysis_framework: Neo4jEngine, git_repository, vuln_type: int,
                 commit_id = None, config_level=None, cve_id=None, custom_sinks: List[str] = None):
        self.analyzer = analysis_framework
        self.patch_commit_id = commit_id if commit_id is not None else 'uk'
        self.git_repository = git_repository
        self.cve_id = cve_id if cve_id is not None else "CVE-0000-0000"
        self.potential_anchor_nodes: AcnhorNodeList[AnchorNode] = AcnhorNodeList()
        self.anchor_functions = []
        self.__compile_anchor_functions(vuln_type, custom_sinks)  # 枚举 sink
        self.__complie_storage_path()
        self.__cache_center = CacheCenter()
        self.__delay_nodes = set()
        self.__level_delay_node: dict[str, set] = {str(i): set() for i in range(3)}
        self.configure = AnchorFinderConfigure(config_level)
        self.potential_sink_funcname = set()

        self.vuln_anchor_function = set()
        # 添加必须经过的路径
        self.patch_sink_path = list()
        self.source_patch_path = list()
        self.current_forward_path = list()
        self.current_backward_path = list()

        self.taint_var_list = set()
        # node_id : (depth, type)
        
        # 全部路径
        self.all_paths = []
        self.callee_forward_depth = dict()
        self.call_stack = []

        # 当从 patch 所在函数向 caller 的栈
        self.caller_stack = []

        # 记录所有到达最大深度的完整调用路径
        self.call_paths = []

        self.caller_paths = []
        
        # 记录所有收集到的call节点（用于其他目的）
        self.collected_call_nodes = []

        self.already_processed_callsite = set()

        self._f_insert = lambda n, judge_type=0b0001, loc=-1: self.potential_anchor_nodes.add(
                AnchorNode.from_node_instance(
                        n, judge_type=judge_type, git_repository=self.git_repository,
                        version=f"{self.patch_commit_id}_prepatch",
                        func_name=self.analyzer.code_step.get_node_code(n), param_loc=loc,
                        file_name=self.analyzer.fig_step.get_belong_file(n),
                        cve_id=self.cve_id
                ), self.analyzer
        )
        self._backup_potential_anchor_nodes: AcnhorNodeList[AnchorNode] = AcnhorNodeList()
        self._bf_insert = lambda n, judge_type=0b0001, loc=-1: self._backup_potential_anchor_nodes.add(
                AnchorNode.from_node_instance(
                        n, judge_type=judge_type, git_repository=self.git_repository,
                        version=f"{self.patch_commit_id}_prepatch",
                        func_name=self.analyzer.code_step.get_node_code(n), param_loc=loc,
                        file_name=self.analyzer.fig_step.get_belong_file(n),
                        cve_id=self.cve_id
                ), self.analyzer
        )

    def _find_outside_exit_identifier(self, cycle_exit_identifier, input_node):
        for _cycle_exit_identifier in cycle_exit_identifier:
            if input_node == _cycle_exit_identifier[0]:
                input_node = self._find_outside_exit_identifier(cycle_exit_identifier, _cycle_exit_identifier[1])
        return input_node

    def forward_cfg_traversal(self, node, cycle_exit_identifier=None, parent_cfg_node=None, node_range=None):
        if node_range is None:
            node_range = [0, 0xfeef]
        if cycle_exit_identifier is None:
            cycle_exit_identifier = {(-0xcaff, -0xcaff)}

        # if node_range[0] > node[NODE_INDEX] or node[NODE_INDEX] > node_range[1]:
        #     return None
        if node is None or node.labels.__str__() != ":" + LABEL_AST:
            return None
        node = self._find_outside_exit_identifier(cycle_exit_identifier, node)
        if node[NODE_LINENO] is None:
            return None

        if parent_cfg_node is not None:
            if node[NODE_LINENO] < parent_cfg_node[NODE_LINENO]:
                if node[NODE_LINENO] == 1 and node[NODE_TYPE] == TYPE_NULL:
                    return
            if parent_cfg_node[NODE_INDEX] not in self.__cache_center.already_traversal_node:
                self.__cache_center.already_traversal_node[parent_cfg_node[NODE_INDEX]] = 1
            else:
                self.__cache_center.already_traversal_node[parent_cfg_node[NODE_INDEX]] += 1

            if self.__cache_center.already_traversal_node[parent_cfg_node[NODE_INDEX]] >= TRAVERSAL_REPORT_THRESHOLD:
                return

        parent_node = self.analyzer.ast_step.get_parent_node(node)

        if parent_node[NODE_TYPE] in {TYPE_WHILE}:
            for _node in self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES):
                self.slice_func_in_line(_node)
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[1].end_node))
                self.forward_cfg_traversal(node=cfg_rel.end_node,
                                           parent_cfg_node=cfg_rel.start_node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0:
            for _node in self.analyzer.ast_step.filter_child_nodes(parent_node, node_type_filter=COMMON_NODE_TYPES):
                self.slice_func_in_line(_node)

            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            # cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([parent_node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel_true, cfg_rel_false = cfg_rels
                self.forward_cfg_traversal(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cycle_exit_identifier=cycle_exit_identifier,
                        node_range=node_range
                )
                self.forward_cfg_traversal(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cycle_exit_identifier=cycle_exit_identifier,
                        node_range=node_range
                )
            elif cfg_rels == 1:
                cfg_rel_true, cfg_rel_false = cfg_rels
                self.forward_cfg_traversal(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cycle_exit_identifier=cycle_exit_identifier,
                        node_range=node_range
                )
                self.forward_cfg_traversal(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cycle_exit_identifier=cycle_exit_identifier,
                        node_range=node_range
                )
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_FOR} and node[NODE_CHILDNUM] == 1:
            for _node in self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES):
                self.slice_func_in_line(_node)

            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add(
                        (self.analyzer.ast_step.get_ith_child_node(parent_node, i=2), cfg_rels[1].end_node))

                self.forward_cfg_traversal(node=cfg_rel.end_node,
                                           parent_cfg_node=cfg_rel.start_node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_FOREACH}:
            for __node in self.analyzer.ast_step.find_child_nodes(node):
                if __node[NODE_TYPE] == TYPE_STMT_LIST: continue
                self.slice_func_in_line(__node)

            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                if cfg_rels[0]['flowLabel'] == 'complete':
                    complete_index, next_index = 0, 1
                else:
                    complete_index, next_index = 1, 0
                cfg_rel = cfg_rels[next_index]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[complete_index].end_node))
                self.forward_cfg_traversal(node=cfg_rel.end_node,
                                           parent_cfg_node=cfg_rel.start_node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_TRY}:
            raise NotImplementedError()
        elif parent_node[NODE_TYPE] in {TYPE_SWITCH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels[-1][CFG_EDGE_FLOW_LABEL] == 'default':
                cfg_rels[-1][
                    CFG_EDGE_FLOW_LABEL] = f"! ( in_array( {TMP_PARAM_FOR_SWITCH},{[i[CFG_EDGE_FLOW_LABEL] for i in cfg_rels[:-2]]}) )"
            for index in range(cfg_rels.__len__()):
                self.forward_cfg_traversal(node=cfg_rels[index].end_node,
                                           parent_cfg_node=cfg_rels[index].start_node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
        else:
            self.slice_func_in_line(node)
            if node[NODE_TYPE] == TYPE_RETURN:
                arg_node = self.analyzer.ast_step.find_function_arg_node_list(node)[-1]
                if self.analyzer.code_step.find_variables(arg_node, VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL):
                    self.__delay_nodes.add(node[NODE_INDEX])
            cfg_next_node = self.analyzer.cfg_step.find_successors(node)
            if cfg_next_node.__len__() == 1:
                pass
            elif cfg_next_node.__len__() == 0:
                return
            else:
                pass
            cfg_next_node = cfg_next_node[-1]
            if node[NODE_TYPE] in {TYPE_EXIT}:
                self.forward_cfg_traversal(node=cfg_next_node, parent_cfg_node=None,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)
            else:
                self.forward_cfg_traversal(node=cfg_next_node, parent_cfg_node=node,
                                           cycle_exit_identifier=cycle_exit_identifier,
                                           node_range=node_range)

    def get_method_call_name(self, node: py2neo.Node) -> str:

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
                    # 处理 var call   多级的 不管了   a->b()->c()
                    method_var_node = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_VAR})
                    if method_var_node:
                        method_var_node = method_var_node[0]
                        method_var_name_nodes = self.analyzer.filter_ast_child_nodes(method_var_node, node_type_filter={TYPE_STRING})
                        method_var_name_nodes = list(sorted(method_var_name_nodes, key=lambda x: x[NODE_INDEX]))
                        method_name = "$"
                        if method_var_name_nodes:
                            method_name += "->".join([n['code'] for n in method_var_name_nodes])
                        method_name_node = self.analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                        if method_name_node:
                            method_name_node = method_name_node[0]
                            method_name += "->" + method_name_node['code']
                        method_call_name = method_name

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
    
        return method_call_name


    def _anchor_function_analysis(self, node: py2neo.Node, TAINT_DYNAMIC_CALL_FLAG: bool = None) -> int:
        """
        只分析单层函数，判断当前 node 是否可能为 sink
        """
        if node[NODE_TYPE] in {TYPE_ECHO, TYPE_PRINT}:
            if self.anchor_functions == FUNCTION_MODEL[10]:
                nn = self.analyzer.ast_step.filter_child_nodes(_node=node, node_type_filter=VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL)
                if nn.__len__() >= 1:
                    return 0b10
                else:
                    return 0b00
            else:
                return 0b00
        elif node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL} \
                and node[NODE_FLAGS][-1] in \
                {FLAG_EXEC_INCLUDE, FLAG_EXEC_INCLUDE_ONCE, FLAG_EXEC_REQUIRE, FLAG_EXEC_REQUIRE_ONCE}:
            if self.anchor_functions == FUNCTION_MODEL[7]:
                return 0b10
            else:
                return 0b00
        elif node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL} \
                and node[NODE_FLAGS][-1] in {FLAG_EXEC_EVAL}:
            if self.anchor_functions == FUNCTION_MODEL[4]:
                return 0b10
            else:
                return 0b00
        code = None
        if node[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
            # 这里处理几种常见的 method_call 情况，太多的就不管了
            # a->b->func()  |  a->func()
            code = self.get_method_call_name(node)
            if not code:
                code = self.analyzer.code_step.get_node_code(node)   
        else:
            code = self.analyzer.code_step.get_node_code(node)
        if code in self.anchor_functions:
            return 0b10
        if code in PHP_BUILT_IN_FUNCTIONS and node[NODE_TYPE] == TYPE_CALL:
            return 0b00
        if node[NODE_TYPE] in {TYPE_NEW, TYPE_STATIC_CALL, TYPE_CALL, TYPE_METHOD_CALL}:
            if self.analyzer.cg_step.find_decl_nodes(node): # 能在调用图中找到 call target
                return 0b01
            else:
                return 0b11     # 保留非 echo/include 的自定义 or 第三方库的函数调用
        return 0b00

    def anchor_function_analysis(self, node, current_level=1, TAINT_DYNAMIC_CALL_FLAG: bool = True):
        """
        沿着 call graph 递归分析函数，判断当前 node 是否可能为 sink
        从 func_decl 开始分析的，就是从新的callee 函数开头，
        """
        # 如果需要记录 callee 的 funcname 的话应该在这个函数内进行
        # 控制 callee 的分析深度
        if current_level >= self.configure.rule_callee_depth:
            if self.current_forward_path:
                path_has_sink = False
                for node in self.current_forward_path:
                    funcname = self.analyzer.code_step.get_node_code(node)
                    node_hash = f"{node[NODE_INDEX]}::{funcname}"
                    func_type = self.__cache_center.already_detect_functions.get(node_hash, 0b00)
                    if func_type == 0b10:
                        path_has_sink = True
                if path_has_sink:
                    self.patch_sink_path.append(self.current_forward_path)
                self.current_forward_path = list()
            return 0b00
        if node[NODE_TYPE] == TYPE_CLASS:
            return 0b00
        assert node[NODE_TYPE] in {TYPE_FUNC_DECL, TYPE_METHOD}

        funcname = self.analyzer.code_step.get_node_code(node)
        node_hash = f"{node[NODE_INDEX]}::{funcname}"
        if node_hash in self.__cache_center.already_detect_functions.keys() and funcname not in self.anchor_functions:
            return self.__cache_center.already_detect_functions[node_hash]
        nodes_todo_analysis = self.analyzer.ast_step.filter_child_nodes(node, max_depth=100,
                                                                        node_type_filter=COMMON_NODE_TYPES) # 找到当前函数中所有函数调用节点
        if nodes_todo_analysis.__len__() == 0:
            self.__cache_center.update_already_detect_functions(node_hash, 0b00)
            
        
        for node_todo_analysis in nodes_todo_analysis:
            result = self._anchor_function_analysis(node_todo_analysis, TAINT_DYNAMIC_CALL_FLAG=TAINT_DYNAMIC_CALL_FLAG)
            if result == 0b00:
                self.__cache_center.update_already_detect_functions(node_hash, 0b00)
            elif result == 0b01 and self.analyzer.cg_step.find_decl_nodes(node_todo_analysis):  # 递归的向下分析callee
                _f = self.anchor_function_analysis(self.analyzer.cg_step.find_decl_nodes(node_todo_analysis)[-1],
                                                   current_level + 1, )
                self.__cache_center.update_already_detect_functions(node_hash, _f)
            elif result == 0b01 and not self.analyzer.cg_step.find_decl_nodes(node_todo_analysis):
                self.__cache_center.update_already_detect_functions(node_hash, 0b00)
            elif result == 0b10:
                self.__cache_center.update_already_detect_functions(node_hash, 0b10)
                self.current_forward_path.append(self.analyzer.cg_step.find_decl_nodes(node_todo_analysis)[-1])
            elif result == 0b11:
                self.__cache_center.update_already_detect_functions(node_hash, 0b11)
            else:
                raise NotImplementedError()
        return self.__cache_center.already_detect_functions[node_hash]


    def slice_func_in_line(self, node: py2neo.Node, taint_var=None) -> bool:
        """
        对于一个 AST call 大类节点，判断其是否为潜在的 sink 节点
        如果可以找到定义，则沿着call edge递归下去继续找
        只判断 sink 点，不判断 其他的
        """
        # 如果一个 node 包含函数调用节点，则他的参数和 taint data 有关，如果继续探索其 callee 的 callsite 就要继续保证和 taint data 有关
        nodes_todo_analysis = self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES)
        for node_todo_analysis in nodes_todo_analysis:
            func_decls = self.analyzer.cg_step.find_decl_nodes(node_todo_analysis)
            if func_decls and func_decls[-1] in self.vuln_anchor_function:
                continue
            args_list = self.analyzer.ast_step.find_function_arg_node_list(node_todo_analysis)
            self.current_forward_path.append(node)
            flag = self._anchor_function_analysis(node_todo_analysis, )
            if flag == 0b00:
                continue
                # 这里把不是的也加进来，扩大范围，交由llm筛选
            elif flag == 0b10:
                # 直接是 sink
                self._f_insert(node_todo_analysis, )
                self.current_forward_path.append(func_decls[-1])
            elif flag == 0b01:  # 在预定义列表中不存在，但是能找到 call 的 decl
                res = self.anchor_function_analysis(func_decls[-1])  # 只需要一个 call target decl 去做 anchor 分析
                if res == 0b10:
                    self._f_insert(node_todo_analysis, )
                    self.current_forward_path.append(func_decls[-1])
            elif flag == 0b11:
                pass

        return True
    
    def _find_enclosing_call_and_param_index(self, node) -> Tuple[Union[py2neo.Node, None], int]:
        """
        From a given AST node, climb parents to find the nearest enclosing call-like node.
        If found, locate which argument index contains the original node.
        Returns (call_node, param_index) or (None, -1).
        """
        if node is None or node.labels.__str__() != ":" + LABEL_AST:
            return None, -1

        call_types = {TYPE_CALL, TYPE_STATIC_CALL, TYPE_METHOD_CALL, TYPE_NEW}
        target = node
        # Climb to the nearest call ancestor
        while target is not None and target[NODE_TYPE] not in call_types:
            parent = self.analyzer.ast_step.get_parent_node(target)
            if parent is None or parent.labels.__str__() != ":" + LABEL_AST:
                return None, -1
            target = parent

        if target is None or target[NODE_TYPE] not in call_types:
            return None, -1

        call_node = target
        # Try to locate arg index
        arg_lists = self.analyzer.ast_step.find_child_nodes(call_node, include_type=[TYPE_ARG_LIST])
        if not arg_lists:
            return call_node, -1
        arg_list_node = arg_lists[0]

        try:
            arg_cnt = self.analyzer.ast_step.get_function_arg_node_cnt(call_node)
        except Exception:
            arg_cnt = -1

        if arg_cnt is None or arg_cnt <= 0:
            return call_node, -1

        param_index = -1
        for i in range(arg_cnt):
            try:
                ith_arg = self.analyzer.ast_step.get_ith_child_node(arg_list_node, i=i)
            except Exception:
                continue
            if ith_arg is None:
                continue
            if ith_arg.identity == node.identity:
                param_index = i
                break
            # Check descendants of this arg
            try:
                descendants = self.analyzer.ast_step.find_child_nodes(ith_arg)
            except Exception:
                descendants = []
            desc_ids = {d.identity for d in descendants} if descendants else set()
            if node.identity in desc_ids:
                param_index = i
                break

        return call_node, param_index
    
    def _maybe_add_call_sink_for_arg_node(self, node):
        """
        If 'node' is used as an argument to a call, and that call is an anchor (directly
        or via callee analysis), add the call to potential anchors with the argument index.
        """
        call_node, param_index = self._find_enclosing_call_and_param_index(node)
        if call_node is None:
            return

        # Reuse existing function/sink analysis logic
        flag = self._anchor_function_analysis(call_node)
        if flag == 0b10:
            self._f_insert(call_node, 0b0010, param_index if param_index is not None else -1)
            return
        if flag == 0b01 and self.analyzer.cg_step.find_decl_nodes(call_node):
            decl = self.analyzer.cg_step.find_decl_nodes(call_node)[-1]
            res = self.anchor_function_analysis(decl)
            if res == 0b10:
                self._f_insert(call_node, 0b0010, param_index if param_index is not None else -1)

    def print_call_paths(self):
        """打印所有调用路径（Caller 段逆向递减缩进，Callee 段正向递增缩进）"""
        print(f"\n=== 发现 {len(self.all_paths)} 条调用路径 ===\n")
        for idx, path in enumerate(self.all_paths, 1):
            print(f"路径 {idx}:")
            # 预计算各段长度，用于 caller 段逆向缩进
            caller_len = sum(1 for c in path if 'level' in c)
            callee_len = sum(1 for c in path if 'depth' in c)

            segment = None  # 'caller' or 'callee'
            caller_idx = 0
            callee_idx = 0

            for call in path:
                curr = 'caller' if 'level' in call else 'callee'
                if curr != segment:
                    segment = curr
                    header = "↑ Caller 段（向上溯源）" if segment == 'caller' else "↓ Callee 段（向下深入）"
                    print(f"  {header}")

                # 计算缩进层级
                if segment == 'caller':
                    indent_level = max(0, (caller_len - 1 - caller_idx))
                else:
                    indent_level = callee_idx

                indent = "    " * indent_level
                tag = f"Caller L{call['level']}" if segment == 'caller' else f"Callee D{call['depth']}"
                name = call['caller_name'] if segment == 'caller' else call['callee_name']

                print(f"{indent}[{tag}] {call['call_site_code']}")
                print(
                    f"{indent}  └─> {('进入上层函数' if segment=='caller' else '进入被调函数')} "
                    f"{name}({call['param_name']}) [污点: {call['taint_var']}]"
                )
                if 'location' in call and call['location']:
                    loc = call['location']
                    print(f"{indent}      @ {loc.get('file', '?')}:{loc.get('line', '?')}")

                # 递增对应段的计数器
                if segment == 'caller':
                    caller_idx += 1
                else:
                    callee_idx += 1
            print()

    def print_callee_paths(self):
        """打印所有调用路径（便于调试）"""
        print(f"\n=== 发现 {len(self.call_paths)} 条调用路径 ===\n")
        
        for idx, path in enumerate(self.call_paths, 1):
            print(f"路径 {idx}:")
            for i, call in enumerate(path):
                indent = "  " * i
                print(f"{indent}[Depth {call['depth']}] {call['call_site_code']}")
                print(f"{indent}  └─> 进入 {call['callee_name']}({call['param_name']}) "
                      f"[污点: {call['taint_var']}]")
                if 'location' in call and call['location']:
                    loc = call['location']
                    print(f"{indent}      @ Line {loc.get('line', '?')}")
            print()


    def _push_call_stack(self, call_site, callee_func, param_node, param_pos, taint_var, depth):
        """
        将调用信息压入栈
        
        Args:
            call_site: 调用点节点
            callee_func: 被调用函数节点
            param_node: 污点形参节点
            taint_var: 污点变量
            depth: 当前深度
        """
        call_info = {
            'call_site': call_site,
            'call_site_code': self.analyzer.code_step.get_node_code(call_site),
            'callee': callee_func,
            'callee_name': self.analyzer.code_step.get_node_code(callee_func),
            'param_node': param_node,
            'param_name': self.analyzer.code_step.get_node_code(param_node) if isinstance(param_node, py2neo.Node) else str(param_node),
            'param_pos': param_pos,
            'taint_var': taint_var,
            'depth': depth,
            'call_site_location': self._get_node_location(call_site)
        }
        self.call_stack.append(call_info)

    def _push_caller_stack(self, call_site, callee_func, param_node, param_pos, taint_var, level):
        """
        将调用信息压入栈
        
        Args:
            call_site: 调用点节点
            callee_func: 被调用函数节点
            param_node: 污点形参节点
            taint_var: 污点变量
            depth: 当前深度
        """
        call_info = {
            'call_site': call_site,
            'call_site_code': self.analyzer.code_step.get_node_code(call_site),
            'caller': callee_func,
            'caller_name': self.analyzer.code_step.get_node_code(callee_func),
            'param_node': param_node,
            'param_name': self.analyzer.code_step.get_node_code(param_node) if isinstance(param_node, py2neo.Node) else str(param_node),
            'param_pos': param_pos,
            'taint_var': taint_var,
            'level': level,
            'call_site_location': self._get_node_location(call_site)
        }
        self.caller_stack.append(call_info)
    
    def _pop_call_stack(self):
        """弹出调用栈"""
        if self.call_stack:
            self.call_stack.pop()

    def _pop_caller_stack(self):
        """弹出调用栈"""
        if self.caller_stack:
            self.caller_stack.pop()
    
    def _record_current_path(self):
        """
        记录当前的完整调用路径
        当达到最大深度时调用
        """
        if not self.call_stack:
            return
        
        # 深拷贝当前调用栈作为一条完整路径
        path = []
        for call_info in self.call_stack:
            path.append({
                'call_site_nodeid': call_info['call_site'][NODE_INDEX],
                'call_site_code': call_info['call_site_code'],
                'callee_name': call_info['callee_name'],
                'param_name': call_info['param_name'],
                'param_pos': call_info['param_pos'],
                'taint_var': call_info['taint_var'],
                'depth': call_info['depth'],
                'location': call_info['call_site_location']
            })
        
        # 添加到路径集合（避免重复）
        if not self._is_duplicate_path(path):
            self.call_paths.append(path)

    def _record_current_caller_path(self):
        """
        记录当前的完整调用路径
        当达到最大深度时调用
        """
        if not self.caller_stack:
            return
        
        # 深拷贝当前调用栈作为一条完整路径
        caller_path = []
        for call_info in self.caller_stack:
            caller_path.append({
                'call_site_nodeid': call_info['call_site'][NODE_INDEX],
                'call_site_code': call_info['call_site_code'],
                'caller_name': call_info['caller_name'],
                'param_name': call_info['param_name'],
                'param_pos': call_info['param_pos'],
                'taint_var': call_info['taint_var'],
                'level': call_info['level'],
                'location': call_info['call_site_location']
            })
        
        if not self._is_duplicate_caller_path(caller_path):
            self.caller_paths.append(caller_path)
            for callee_path in self.call_paths:
                callee_path[:0] = caller_path

        self.all_paths.extend(self.call_paths)
        self.call_paths.clear()

    
    def _is_duplicate_path(self, new_path):
        """检查路径是否已存在，这部分效率低，后续可以优化"""  
        for existing_path in self.call_paths:
            if self._paths_equal(existing_path, new_path):
                return True
        return False
    
    def _is_duplicate_caller_path(self, new_path):
        """检查路径是否已存在，这部分效率低，后续可以优化"""  
        for existing_path in self.caller_paths:
            if self._caller_paths_equal(existing_path, new_path):
                return True
        return False
    
    def _paths_equal(self, path1, path2):
        """比较两条路径是否相同"""
        if len(path1) != len(path2):
            return False
        
        for i in range(len(path1)):
            if (path1[i]['call_site_code'] != path2[i]['call_site_code'] or
                path1[i]['callee_name'] != path2[i]['callee_name']):
                return False
        
        return True
    
    def _caller_paths_equal(self, path1, path2):
        """比较两条路径是否相同"""
        if len(path1) != len(path2):
            return False
        
        for i in range(len(path1)):
            if (path1[i]['call_site_code'] != path2[i]['call_site_code'] or
                path1[i]['caller_name'] != path2[i]['caller_name']):
                return False
        
        return True
    
    def _get_node_location(self, node):
        """获取节点位置信息"""
        location = {}
        if NODE_LINENO in node:
            location['line'] = node[NODE_LINENO]
        if NODE_FILEID in node:
            location['file'] = self.analyzer.fig_step.get_belong_file(node)
        return location


    def _analyze_callee_function(self, func_decl_node, taint_param_node, call_node, taint_var, depth):
        
        if depth > 2:
            self._record_current_path()
            return
        
        param_name = self.analyzer.code_step.get_node_code(taint_param_node)[1:]  # 去掉 $
        use_nodes = self.analyzer.pdg_step.find_use_nodes(taint_param_node)

        # 对每个使用点进行前向遍历
        for use_node in use_nodes:
            # 标记污点变量
            use_node['taint_var'] = param_name
            self.forward_pdg_traversal(use_node, param_name, depth)


    def _handle_call_node(self, node, taint_var, depth=0):
        # assert taint_var is not None
        # node 就是 callsite node
        # TODO 再加个缓存，对于同一个 taint 同一个 node 的 handle 进行缓存
        if taint_var is None:
            return
        func_decls = self.analyzer.cg_step.find_decl_nodes(node)
        # 这里需要加上 _anchor 的那个判断，即如果在预定义集中则 f_insert
        if func_decls:
            func_decl = func_decls[-1]
            if func_decl in self.vuln_anchor_function:
                return
            func_name = self.analyzer.code_step.get_node_code(func_decl)
            if func_name == "db_fetch_assoc":
                print("db")
        else:
            return
        taint_arg_num = -1
        node_hash = f"{func_decl[NODE_INDEX]}::{func_name}"
        ana_result = self._anchor_function_analysis(node)
        self.__cache_center.update_already_detect_functions(node_hash, ana_result)
        if ana_result == 0b10:
            self._f_insert(node, )
        args_list = self.analyzer.ast_step.find_function_arg_node_list(node)
        for arg_node_key in args_list.keys():
            if arg_node_key == f"${taint_var}":
                taint_arg_num = args_list[arg_node_key]
                break
        # 处理 call node，找得到 decls 在if，否则在 else，例如 built-in 函数
        depth = depth + 1
        params_list = self.analyzer.ast_step.find_function_param_node_list(func_decl)
        if params_list.__len__() != 0 and taint_arg_num > -1:
            for param_node in params_list:
                if param_node[NODE_CHILDNUM] == taint_arg_num:
                    self._push_call_stack(node, func_decls[-1], param_node, taint_arg_num, taint_var, depth)
                    # 去分析 callee 的里面，如果是预定义的函数
                    self._analyze_callee_function(
                        func_decls[-1], 
                        param_node,
                        node,
                        taint_var,
                        depth
                    )
                    # 返回后弹出调用栈
                    self._pop_call_stack()
                    break
        else:
            if taint_arg_num != -1:     # taint reach 到了某个语句，但是并没有reach到这个语句的参数部分
                self._push_call_stack(node, func_decls[-1], f"${taint_var}", taint_arg_num, taint_var, depth)
                self._record_current_path()
                self._pop_call_stack()
        return

    def forward_pdg_traversal(self, node, taint_var=None, depth=0, level=0):
        # forward 递归和 call graph 是两回事
        if depth > 2:
            self._record_current_path()
            return 
        _node = self.analyzer.get_ast_root_node(node)
        if _node is None:
            return 
        if _node.identity in self.__cache_center.already_visit_pdg_node:
            return 
        else:
            self.__cache_center.already_visit_pdg_node.add(_node.identity)

        # 碰到 call 相关节点
        calleesite_nodes = self.analyzer.ast_step.filter_child_nodes(_node, node_type_filter=COMMON_NODE_TYPES)
        if calleesite_nodes:
            for calleesite_node in calleesite_nodes:
                self._handle_call_node(calleesite_node, taint_var=taint_var, depth=depth)
                
        # 对 return node 的处理
        if node[NODE_TYPE] == TYPE_RETURN:
            # 记录一下如果需要分析上级 caller  只有分析 patch 和其 caller 所在函数才需要
            if depth <= 0:
                arg_node = self.analyzer.ast_step.find_function_arg_node_list_old(node)[-1]

                if self.analyzer.code_step.find_variables(arg_node, VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL):
                    # self.__delay_nodes.add(node[NODE_INDEX])
                    self.__level_delay_node[str(level)].add(node[NODE_INDEX])

        # 沿着 use 边继续寻找 use node
        _reach_to_nodes = self.analyzer.pdg_step.find_use_nodes(_node)
        if _reach_to_nodes.__len__() == 0:
            return 
        
        taint_var = _node['taint_var']
        if taint_var is not None:
            self.taint_var_list.add(taint_var)
        # 这部分是单层内的forward    这里的 forward 并不跨call graph，只是跨 data flow
        for _reach_to_node in _reach_to_nodes:
            taint_var = _reach_to_node['taint_var']
            self.forward_pdg_traversal(_reach_to_node, taint_var=taint_var, depth=depth, level=level)

    def load_sinks(self) -> bool:
        if os.path.exists(self.sink_storage_path):
            with open(self.sink_storage_path, "r") as f:
                sink_list = json.load(f)
            for node_dict in sink_list:
                node = self.analyzer.get_node_itself(node_dict['id'])
                self.potential_anchor_nodes.add_without_check(
                    AnchorNode.from_node_instance(
                        node, judge_type=node_dict['judge_type'], param_loc=node_dict['loc'],
                        git_repository=self.git_repository,
                        version=f"{self.patch_commit_id}_prepatch",
                        func_name=self.analyzer.code_step.get_node_code(node), 
                        file_name=self.analyzer.fig_step.get_belong_file(node),
                        cve_id=self.cve_id
                    )
                )
            return True
        else:
            return False
        
    def load_all_paths(self):
        # 使用 pickle 加载 self.all_paths
        with open(os.path.join(STORAGE_PATH, 'cve_sink_finder', f'all_paths_{self.cve_id}_{self.patch_commit_id}.pkl'), 'rb') as f:
            self.all_paths = pickle.load(f)

        return True

    def store_sinks(self):
        storage_sink_list = [{"id": i.node_id, "judge_type": i.judge_type, "loc": i.param_loc[-1]} 
                             for i in self.potential_anchor_nodes]
        if storage_sink_list:
            with open(self.sink_storage_path, "w") as f:
                json.dump(obj=storage_sink_list, fp=f)

    def traversal_initiation(self, node) -> Tuple[List[py2neo.Node], List[py2neo.Node]]:
        result_cfg_pdg_begin_lines = []
        result_pdg_begin_lines = []
        node = self.analyzer.get_node_itself(node)
        if node[NODE_TYPE] in {TYPE_THROW}:
            node = self.analyzer.ast_step.get_child_node(node)
        parent_node = self.analyzer.ast_step.get_parent_node(node)
        if node[NODE_TYPE] in {TYPE_ASSIGN, TYPE_ASSIGN_OP, TYPE_ASSIGN_REF}: # 只有当 node 是赋值的时候才会管 pdg
            rr = self.analyzer.pdg_step.find_use_nodes(node)  # 找到当前 node 的 use 节点，看有哪些节点 use 了当前 node
            if not rr:
                l_var = self.analyzer.ast_step.get_child_node(node)
                if l_var[NODE_TYPE] == TYPE_DIM and self.analyzer.code_step.get_ast_dim_code(l_var).endswith("[]"):  # 这里好像处理的就是  a[] = xxx 这种形式，php 数组中的元素赋值
                    start, end = self.analyzer.range_step.get_general_node_range(
                            self.analyzer.get_node_itself(node[NODE_FUNCID]))   # 获取当前 node 所在函数的范围
                    for _node, in self.analyzer.basic_step.run(
                            "MATCH (B:AST)-[:PARENT_OF]->(C:AST) "
                            f"WHERE B.type = '{TYPE_VAR}'"
                            f" AND C.code = '{self.analyzer.code_step.get_ast_dim_code(l_var).rstrip('[]').lstrip('$')}'"
                            f" AND B.id>={start} and B.id <= {end} "
                            f" RETURN B;"
                    ):
                        result_pdg_begin_lines.append(_node)
            else:
                result_pdg_begin_lines.append(node)
            rr = []
        elif parent_node[NODE_TYPE] in {TYPE_THROW}:
            rr = []
        elif (parent_node[NODE_TYPE] in {TYPE_FOR} and node[NODE_CHILDNUM] == 1) or \
                (parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0) or \
                (node[NODE_TYPE] in {TYPE_FOREACH}) or \
                (node[NODE_TYPE] in {TYPE_WHILE}):
            start, end = self.analyzer.range_step.get_general_node_range(node)
            self.__cache_center.update_already_taint_edge(start, end)
            rr = [node]
        elif node[NODE_TYPE] in {TYPE_EXIT}:
            if self.anchor_functions == FUNCTION_MODEL[10] and node[NODE_TYPE] in {TYPE_EXIT}:
                self._f_insert(node, 0b0001, 0)
            self.slice_func_in_line(node)
            rr = self.analyzer.cfg_step.find_successors(node)
        elif node[NODE_TYPE] in {TYPE_CALL, TYPE_STATIC_CALL, TYPE_METHOD_CALL, TYPE_NEW}:
            self.slice_func_in_line(node)
            if self.analyzer.cg_step.find_decl_nodes(node):
                is_anchor_function = self.anchor_function_analysis(self.analyzer.cg_step.find_decl_nodes(node)[0])
                arg_list_node = self.analyzer.ast_step.find_child_nodes(node, include_type=[TYPE_ARG_LIST])[0]
                if is_anchor_function and self.analyzer.code_step.find_variables(arg_list_node, VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL):
                    self._f_insert(node, 0b0010, -1)
            rr = []
        elif node[NODE_TYPE] in {TYPE_UNSET, TYPE_ECHO, TYPE_PRINT}:
            for _node in self.analyzer.ast_step.find_child_nodes(node):
                self.slice_func_in_line(_node)
            rr = []
        else:
            rr = []
        result_cfg_pdg_begin_lines.extend(rr)
        global_vars = self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=[TYPE_DIM], )    # 这里的 global var 只想看经过post get 等处理的元素访问
        rr = [i for i in global_vars if
              self.analyzer.code_step.get_ast_dim_body_code(i) in {"_POST", "_GET", "_REQUEST", "_FILE", "_COOKIE"}]
        result_cfg_pdg_begin_lines.extend(rr)
        if self.analyzer.code_step.get_node_code(node) in self.anchor_functions \
                and self.analyzer.ast_step.get_function_arg_node_cnt(node) >= 1 \
                and self.analyzer.code_step.find_variables(node, VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL):
            self._f_insert(node, 0b0001, 0)
        elif node[NODE_TYPE] == TYPE_RETURN:
            self.__delay_nodes.add(node[NODE_INDEX])
        elif self.analyzer.basic_step.get_node_itself(node[NODE_FUNCID])[NODE_TYPE] in {TYPE_FUNC_DECL, TYPE_METHOD}:
            for x in self.analyzer.ast_step.find_function_return_expr(
                    self.analyzer.basic_step.get_node_itself(node[NODE_FUNCID])):
                if x[NODE_INDEX] >= node[NODE_INDEX]:
                    self.__delay_nodes.add(x[NODE_INDEX])   # 添加了node之后的能到exit的节点
        return result_pdg_begin_lines, result_cfg_pdg_begin_lines

    def traversal(self, level=0) -> bool:

        # 直接定位 sink
        # if self.load_sinks():
        #     return True

        query = f"match (n:AST) where n.type in {COMMON_NODE_TYPES} return n"
        # print(query)
        for node, in self.analyzer.basic_step.run(query):
            result = self._anchor_function_analysis(node)
            if result == 0b10:
                self._f_insert(node, )

    def find_node_in_list(self, node, node_list: List[ModifiedLine]) -> bool:
        for n in node_list:
            if n.root_node == node[NODE_INDEX]:
                return True
        return False