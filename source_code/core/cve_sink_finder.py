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
from core.core_utils import *

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
        # 
        # sinkcallee1caller0
        # sinkcallee2caller1
        # sinkcallee3caller2
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


class CVESinkFinder(object):
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
                 commit_id = None, config_level=None, cve_id=None, custom_sinks: List[str] = None, max_caller_depth = 1, max_callee_depth = 1):
        self.analyzer = analysis_framework
        self.patch_commit_id = commit_id if commit_id is not None else 'uk'
        self.git_repository = git_repository
        self.cve_id = cve_id if cve_id is not None else "CVE-0000-0000"
        self.potential_anchor_nodes: AcnhorNodeList[AnchorNode] = AcnhorNodeList()
        self.anchor_functions = []
        self.vuln_type = vuln_type
        self.__compile_anchor_functions(vuln_type, custom_sinks)  #  sink
        self.__complie_storage_path()
        self.__cache_center = CacheCenter()
        self.__delay_nodes = set()
        self.__level_delay_node: dict[str, set] = {str(i): set() for i in range(3)}
        self.configure = AnchorFinderConfigure(config_level)
        self.potential_sink_funcname = set()

        self.vuln_anchor_function = set()
        # 
        self.patch_sink_path = list()
        self.source_patch_path = list()
        self.current_forward_path = list()
        self.current_backward_path = list()

        self.taint_var_list = set()
        # node_id : (depth, type)
        
        self.max_caller_depth = max_caller_depth
        self.max_callee_depth = max_callee_depth

        # 
        self.all_paths = []
        self.callee_forward_depth = dict()
        self.call_stack = []

        #  patch  caller 
        self.caller_stack = []

        # 
        self.call_paths = []

        self.caller_paths = []
        
        # call
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
                result = self.analyzer.ast_step.find_function_arg_node_list_old(node)
                if result:
                    arg_node = result[-1]
                    if self.analyzer.code_step.find_variables(arg_node, VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL):
                        self.__delay_nodes.add(node[NODE_INDEX])
                else:
                    pass
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
                

    def _anchor_function_analysis(self, node: py2neo.Node, TAINT_DYNAMIC_CALL_FLAG: bool = None) -> int:
        """
         node  sink
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
            code = get_method_call_name(self.analyzer, node)
            if not code:
                code = self.analyzer.code_step.get_node_code(node)   
        else:
            code = self.analyzer.code_step.get_node_code(node)
        if code in self.anchor_functions:
            return 0b10
        if code in PHP_BUILT_IN_FUNCTIONS and node[NODE_TYPE] == TYPE_CALL:
            return 0b00
        if node[NODE_TYPE] in {TYPE_NEW, TYPE_STATIC_CALL, TYPE_CALL, TYPE_METHOD_CALL}:
            if self.analyzer.cg_step.find_decl_nodes(node): #  call target
                return 0b01
            else:
                return 0b11     
        return 0b00

    def anchor_function_analysis(self, node, current_level=1, TAINT_DYNAMIC_CALL_FLAG: bool = True):
        """
         call graph  node  sink
         func_decl callee 
        """
        #  callee  funcname 
        #  callee 
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
                                                                        node_type_filter=COMMON_NODE_TYPES) # 
        if nodes_todo_analysis.__len__() == 0:
            self.__cache_center.update_already_detect_functions(node_hash, 0b00)
            
        
        for node_todo_analysis in nodes_todo_analysis:
            result = self._anchor_function_analysis(node_todo_analysis, TAINT_DYNAMIC_CALL_FLAG=TAINT_DYNAMIC_CALL_FLAG)
            if result == 0b00:
                self.__cache_center.update_already_detect_functions(node_hash, 0b00)
            elif result == 0b01 and self.analyzer.cg_step.find_decl_nodes(node_todo_analysis):  # callee
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
         AST call  sink 
        call edge
         sink  
        """
        #  node  taint data  callee  callsite  taint data 
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
                # llm
            elif flag == 0b10:
                #  sink
                self._f_insert(node_todo_analysis, )
                if func_decls:
                    self.current_forward_path.append(func_decls[-1])
            elif flag == 0b01:  #  call  decl
                res = self.anchor_function_analysis(func_decls[-1])  #  call target decl  anchor 
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
        """Caller Callee """
        print(f"\n===  {len(self.all_paths)}  ===\n")
        for idx, path in enumerate(self.all_paths, 1):
            print(f" {idx}:")
            #  caller 
            caller_len = sum(1 for c in path if 'level' in c)
            callee_len = sum(1 for c in path if 'depth' in c)

            segment = None  # 'caller' or 'callee'
            caller_idx = 0
            callee_idx = 0

            for call in path:
                curr = 'caller' if 'level' in call else 'callee'
                if curr != segment:
                    segment = curr
                    header = "↑ Caller " if segment == 'caller' else "↓ Callee "
                    print(f"  {header}")

                # 
                if segment == 'caller':
                    indent_level = max(0, (caller_len - 1 - caller_idx))
                else:
                    indent_level = callee_idx

                indent = "    " * indent_level
                tag = f"Caller L{call['level']}" if segment == 'caller' else f"Callee D{call['depth']}"
                name = call['caller_name'] if segment == 'caller' else call['callee_name']

                print(f"{indent}[{tag}] {call['call_site_code']}")
                print(
                    f"{indent}  └─> {('' if segment=='caller' else '')} "
                    f"{name}({call['param_name']}) [: {call['taint_var']}]"
                )
                if 'location' in call and call['location']:
                    loc = call['location']
                    print(f"{indent}      @ {loc.get('file', '?')}:{loc.get('line', '?')}")

                # 
                if segment == 'caller':
                    caller_idx += 1
                else:
                    callee_idx += 1
            print()

    def print_callee_paths(self):
        """"""
        print(f"\n===  {len(self.call_paths)}  ===\n")
        
        for idx, path in enumerate(self.call_paths, 1):
            print(f" {idx}:")
            for i, call in enumerate(path):
                indent = "  " * i
                print(f"{indent}[Depth {call['depth']}] {call['call_site_code']}")
                print(f"{indent}  └─>  {call['callee_name']}({call['param_name']}) "
                      f"[: {call['taint_var']}]")
                if 'location' in call and call['location']:
                    loc = call['location']
                    print(f"{indent}      @ Line {loc.get('line', '?')}")
            print()

    def print_potential_sink_funcname(self):
        """ sink """
        print(f"\n===  {len(self.potential_sink_funcname)}  sink  ===\n")
        for funcname in self.potential_sink_funcname:
            print(f"- {funcname}")
        print()


    def _push_call_stack(self, call_site, callee_func, param_node, param_pos, taint_var, depth, callee_name=None):
        """
        
        
        Args:
            call_site: 
            callee_func: 
            param_node: 
            taint_var: 
            depth: 
        """
        call_info = {
            'call_site': call_site,
            'call_site_code': self.analyzer.code_step.get_node_code(call_site),
            'callee': callee_func,
            'callee_name': callee_name if callee_name is not None else self.analyzer.code_step.get_node_code(callee_func),
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
        
        
        Args:
            call_site: 
            callee_func: 
            param_node: 
            taint_var: 
            depth: 
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
        """"""
        if self.call_stack:
            self.call_stack.pop()

    def _pop_caller_stack(self):
        """"""
        if self.caller_stack:
            self.caller_stack.pop()
    
    def _record_current_path(self):
        """
        
        
        """
        if not self.call_stack:
            return
        
        # 
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
        
        # 
        if not self._is_duplicate_path(path):
            self.call_paths.append(path)

    def _record_current_caller_path(self):
        """
        
        
        """
        if not self.caller_stack:
            return
        
        # 
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

    def _record_current_caller_path_one(self):
        """
        
        
        """
        
        # 
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
        """"""  
        for existing_path in self.call_paths:
            if self._paths_equal(existing_path, new_path):
                return True
        return False
    
    def _is_duplicate_caller_path(self, new_path):
        """"""  
        for existing_path in self.caller_paths:
            if self._caller_paths_equal(existing_path, new_path):
                return True
        return False
    
    def _paths_equal(self, path1, path2):
        """"""
        if len(path1) != len(path2):
            return False
        
        for i in range(len(path1)):
            if (path1[i]['call_site_code'] != path2[i]['call_site_code'] or
                path1[i]['callee_name'] != path2[i]['callee_name']):
                return False
        
        return True
    
    def _caller_paths_equal(self, path1, path2):
        """"""
        if len(path1) != len(path2):
            return False
        
        for i in range(len(path1)):
            if (path1[i]['call_site_code'] != path2[i]['call_site_code'] or
                path1[i]['caller_name'] != path2[i]['caller_name']):
                return False
        
        return True
    
    def _get_node_location(self, node):
        """"""
        location = {}
        if NODE_LINENO in node:
            location['line'] = node[NODE_LINENO]
        if NODE_FILEID in node:
            location['file'] = self.analyzer.fig_step.get_belong_file(node)
        return location


    def _analyze_callee_function(self, func_decl_node, taint_param_node, call_node, taint_var, depth):
        
        if depth > self.max_callee_depth:
            self._record_current_path()
            return
        
        param_name = self.analyzer.code_step.get_node_code(taint_param_node)[1:]  #  $
        use_nodes = self.analyzer.pdg_step.find_use_nodes(taint_param_node)

        # 
        for use_node in use_nodes:
            # 
            use_node['taint_var'] = param_name
            self.forward_pdg_traversal(use_node, param_name, depth)


    def _handle_call_node(self, node, taint_var, depth=0):
        # assert taint_var is not None
        # node  callsite node            method node  static call node
        # TODO  taint  node  handle 
        # if taint_var is None:
        #     return
        
        call_decl = None
        callee_name = None

        #  method call  decl node method call 
        if node[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
            #  $this->method() $this->db->method()
            #  var call prop call
            #   $this->db->get()->result_array();  method_call method_call  

            #  prop call
            method_call_name = get_method_call_name(self.analyzer, node)
            
            if method_call_name is None:
                return
            callee_name = method_call_name
            method_decls = self.analyzer.cg_step.find_decl_nodes(node)
                
            if method_decls:
                method_decl = method_decls[-1]
                node_hash = f"{method_decl[NODE_INDEX]}::{method_call_name}"
                ana_result = self._anchor_function_analysis(node)
                if ana_result == 0b10:
                    self._f_insert(node, )
                self.__cache_center.update_already_detect_functions(node_hash, ana_result)
                call_decl = method_decl

            else:
                node_hash = f"{node[NODE_INDEX]}::{method_call_name}"
                ana_result = self._anchor_function_analysis(node)
                if ana_result == 0b10:
                    self._f_insert(node, )
                self.__cache_center.update_already_detect_functions(node_hash, ana_result)
                return

        else:
            func_decls = self.analyzer.cg_step.find_decl_nodes(node)
            if func_decls:
                func_decl = func_decls[-1]
                if func_decl in self.vuln_anchor_function:
                    return
                func_name = self.analyzer.code_step.get_node_code(func_decl)
                if func_name == "db_fetch_assoc":
                    print("db")
                node_hash = f"{func_decl[NODE_INDEX]}::{func_name}"
                ana_result = self._anchor_function_analysis(node)
                if ana_result == 0b10:
                    self._f_insert(node, )
                self.__cache_center.update_already_detect_functions(node_hash, ana_result)
                call_decl = func_decl
                callee_name = func_name
            else:
                ana_result = self._anchor_function_analysis(node)
                if ana_result == 0b10:
                    self._f_insert(node, )
                return
            
        taint_arg_num = -1
        #  decl
        args_list = self.analyzer.ast_step.find_function_arg_node_list(node)
        for arg_node_key in args_list.keys():
            if arg_node_key == f"${taint_var}":
                taint_arg_num = args_list[arg_node_key]
                break
        #  call node decls if else built-in 
        depth = depth + 1
        params_list = self.analyzer.ast_step.find_function_param_node_list(call_decl)
        if params_list.__len__() != 0 and taint_arg_num > -1:
            for param_node in params_list:
                if param_node[NODE_CHILDNUM] == taint_arg_num:
                    self._push_call_stack(node, call_decl, param_node, taint_arg_num, taint_var, depth, callee_name)
                    #  callee 
                    self._analyze_callee_function(
                        call_decl, 
                        param_node,
                        node,
                        taint_var,
                        depth
                    )
                    # 
                    # self._record_current_path()
                    self._pop_call_stack()
                    break
        else:
            if taint_arg_num != -1:     # taint reach reach
                self._push_call_stack(node, call_decl, f"${taint_var}", taint_arg_num, taint_var, depth, callee_name)
                self._record_current_path()
                self._pop_call_stack()
        return

    def forward_pdg_traversal(self, node, taint_var=None, depth=0, level=0):
        # forward  call graph 
        if depth > self.max_callee_depth:
            self._record_current_path()
            return 
        _node = self.analyzer.get_ast_root_node(node)
        if _node is None:
            return 
        if _node.identity in self.__cache_center.already_visit_pdg_node:
            return 
        else:
            self.__cache_center.already_visit_pdg_node.add(_node.identity)

        #  call 
        calleesite_nodes = self.analyzer.ast_step.filter_child_nodes(_node, node_type_filter=COMMON_NODE_TYPES)
        if calleesite_nodes:
            for calleesite_node in calleesite_nodes:
                self._handle_call_node(calleesite_node, taint_var=taint_var, depth=depth)
                
        #  return node 
        if node[NODE_TYPE] == TYPE_RETURN:
            #  caller   patch  caller 
            if depth <= 0:
                arg_node = self.analyzer.ast_step.find_function_arg_node_list_old(node)[-1]

                if self.analyzer.code_step.find_variables(arg_node, VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL):
                    # self.__delay_nodes.add(node[NODE_INDEX])
                    self.__level_delay_node[str(level)].add(node[NODE_INDEX])

        #  use  use node
        _reach_to_nodes = self.analyzer.pdg_step.find_use_nodes(_node)
        if _reach_to_nodes.__len__() == 0:
            return 
        
        taint_var = _node['taint_var']
        if taint_var is not None:
            self.taint_var_list.add(taint_var)
        # forward     forward call graph data flow
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
        #  pickle  self.all_paths
        try:
            with open(os.path.join(STORAGE_PATH, 'cve_sink_finder', str(self.vuln_type), f'all_paths_{self.cve_id}_{self.patch_commit_id}.pkl'), 'rb') as f:
                self.all_paths = pickle.load(f)

            with open(os.path.join(STORAGE_PATH, 'cve_sink_finder', str(self.vuln_type), f'all_potential_sink_funcname_{self.cve_id}_{self.patch_commit_id}.pkl'), 'rb') as f:
                self.potential_sink_funcname = pickle.load(f)

            return True
        except FileNotFoundError:
            return False

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
        if node[NODE_TYPE] in {TYPE_ASSIGN, TYPE_ASSIGN_OP, TYPE_ASSIGN_REF}: #  node  pdg
            rr = self.analyzer.pdg_step.find_use_nodes(node)  #  node  use  use  node
            if not rr:
                l_var = self.analyzer.ast_step.get_child_node(node)
                if l_var[NODE_TYPE] == TYPE_DIM and self.analyzer.code_step.get_ast_dim_code(l_var).endswith("[]"):  #   a[] = xxx php 
                    start, end = self.analyzer.range_step.get_general_node_range(
                            self.analyzer.get_node_itself(node[NODE_FUNCID]))   #  node 
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
            #  anchor pdg 
            result_pdg_begin_lines.append(node)
            rr = []
        elif node[NODE_TYPE] in {TYPE_UNSET, TYPE_ECHO, TYPE_PRINT}:
            for _node in self.analyzer.ast_step.find_child_nodes_and_itself(node):
                self.slice_func_in_line(_node)
            rr = []
        else:
            rr = []
        result_cfg_pdg_begin_lines.extend(rr)
        global_vars = self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=[TYPE_DIM], )    #  global var post get 
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
                    self.__delay_nodes.add(x[NODE_INDEX])   # nodeexit
        return result_pdg_begin_lines, result_cfg_pdg_begin_lines




    def traversal(self, level=0) -> bool:
        self.patch_analysis_result: Dict[str, List[ModifiedLine]] = \
            json.load(object_hook=lambda x: ModifiedLine(**x) if 'lineno' in x.keys() else x,
                      fp=open(os.path.join(STORAGE_PATH, 'patch_analysis_result', "results", f'res_{self.patch_commit_id}.json')))
        
        if self.load_sinks():    
            self.load_all_paths()
            return True

        if self.load_all_paths():
            self.print_call_paths()
            self.print_potential_sink_funcname()
            return False

        def traversal_recur(level):
            if level > self.max_caller_depth:       #  level  caller 
                return False
            # if self.load_sinks():
            #     return True
            #  sink sink   callee  sink
            for file, affect_line in self.patch_analysis_result.items():
                traversal_structure_pure_pdg: List[py2neo.Node] = []
                traversal_structure_cfg_pdg: List[py2neo.Node] = []
                for affect_node in affect_line:
                    pure_pdg, cfg_pdg = self.traversal_initiation(affect_node.root_node, )
                    traversal_structure_pure_pdg.extend(pure_pdg)
                    traversal_structure_cfg_pdg.extend(cfg_pdg)
                traversal_structure_pure_pdg = sorted(set(traversal_structure_pure_pdg), key=lambda x: x.identity)
                traversal_structure_cfg_pdg = sorted(set(traversal_structure_cfg_pdg), key=lambda x: x.identity)
                ret_taint_var = None
                for node in traversal_structure_pure_pdg:
                    self.forward_pdg_traversal(node, level=level)
                    # self.print_callee_paths()
                    # exit(0)
                for node in traversal_structure_cfg_pdg:
                    if node.labels.__str__() == ":Artificial": continue
                    _range = self.analyzer.range_step.get_general_node_range(node)
                    self.forward_cfg_traversal(node, node_range=_range)
            if self.potential_anchor_nodes.__len__() == 0:
                #  return 
                if self.__level_delay_node[str(level)].__len__() >= 1 \
                        and self.configure.configure_level <= self.configure.configure_max_level:
                    self.patch_analysis_result = dict()
                    for i in self.__level_delay_node[str(level)]:
                        i = self.analyzer.basic_step.get_node_itself(i)
                        if i[NODE_TYPE] != TYPE_RETURN: continue
                        func_node = self.analyzer.basic_step.get_node_itself(i[NODE_FUNCID])    # 
                        if func_node == None: continue
                        #  caller patch 
                        if level == 0:
                            self.vuln_anchor_function.add(func_node)
                            self._push_caller_stack(i, func_node, i, "","ret val", 0)
                            self.all_paths.extend(self.call_paths)
                            self.call_paths.clear()
                        if level > 0:
                            self._record_current_caller_path()
                            self.call_paths.clear()
                            self.vuln_anchor_function.add(func_node)
                        if func_node[NODE_TYPE] in {TYPE_FUNC_DECL, TYPE_METHOD}:
                            call_sites = self.analyzer.cg_step.find_call_nodes(func_node)   #  call 
                            if 1 <= call_sites.__len__() and call_sites.__len__() <= 10:
                                call_sites = sorted(call_sites, key=lambda x: x.identity)[:3]  # 3 callsite 
                                for call_site in call_sites:
                                    if call_site not in self.already_processed_callsite:
                                        self.already_processed_callsite.add(call_site)
                                    else:
                                        continue
                                    file_node = self.analyzer.neo4j_graph.nodes.match(id=call_site["fileid"]).first()
                                    top_level_node = self.analyzer.neo4j_graph.relationships.match((file_node, None), r_type="FILE_OF").first().end_node
                                    caller_func_node = self.analyzer.basic_step.get_node_itself(call_site[NODE_FUNCID]) 
                                    file_path = top_level_node["name"]
                                    if file_path not in self.patch_analysis_result.keys():
                                        self.patch_analysis_result[file_path] = []
                                    _root_node = self.analyzer.ast_step.get_root_node(call_site)
                                    if not self.find_node_in_list(_root_node, self.patch_analysis_result[file_path]):
                                        self.patch_analysis_result[file_path].append(ModifiedLine(_root_node[NODE_LINENO], _root_node[NODE_INDEX], _root_node[NODE_TYPE], ))
                                    self._push_caller_stack(call_site, caller_func_node, _root_node, "","ret val", level + 1)
                                    self.__level_delay_node[str(level + 1)] = set()
                                    for file_path in self.patch_analysis_result.keys():
                                        self.patch_analysis_result[file_path] = sorted(self.patch_analysis_result[file_path], key=lambda x: x.lineno)
                                    if self.patch_analysis_result:
                                        traversal_recur(level + 1)
                                self._pop_caller_stack()
                else:   #  return  caller 
                    if level > 0:
                        self._record_current_caller_path()
                        self.call_paths.clear()
                        self._pop_caller_stack()
                    else:
                        self.all_paths.extend(self.call_paths)
                        self.call_paths.clear()
                        return
            else:
                if self.call_paths:
                    self._record_current_caller_path_one()
                    self.call_paths.clear()
                return
        

        traversal_recur(level)
        self.print_call_paths()

            
        for node_hash in self.__cache_center.already_detect_functions.keys():
            node_id = int(node_hash.split("::")[0])
            func_name = node_hash.split("::")[1]
            node = self.analyzer.get_node_itself(node_id)
            func_args_str = self.analyzer.ast_step.find_function_arg_node_list(node)
            func_signature = func_name
            for args in func_args_str:
                func_signature += args + ", "
            if func_args_str:
                func_signature += "("
                func_signature = func_signature[:-2] + ")"
            else:
                func_signature += "()"

            self.potential_sink_funcname.add(func_signature)
                
        if self.potential_anchor_nodes.__len__()  != 0:
            self.store_sinks()

        # self.all_paths
        #  pickle  self.all_paths
        os.makedirs(os.path.join(STORAGE_PATH, 'cve_sink_finder', str(self.vuln_type)), exist_ok=True)
        with open(os.path.join(STORAGE_PATH, 'cve_sink_finder', str(self.vuln_type), f'all_paths_{self.cve_id}_{self.patch_commit_id}.pkl'), 'wb') as f:
            pickle.dump(self.all_paths, f)

        os.makedirs(os.path.join(STORAGE_PATH, 'cve_sink_finder', str(self.vuln_type)), exist_ok=True)
        with open(os.path.join(STORAGE_PATH, 'cve_sink_finder', str(self.vuln_type), f'all_potential_sink_funcname_{self.cve_id}_{self.patch_commit_id}.pkl'), 'wb') as f:
            pickle.dump(self.potential_sink_funcname, f)
        
        if self.configure.configure_level >= self.configure.configure_max_level:
            return True
        return not (self.potential_anchor_nodes.__len__() == 0)

    def find_node_in_list(self, node, node_list: List[ModifiedLine]) -> bool:
        for n in node_list:
            if n.root_node == node[NODE_INDEX]:
                return True
        return False