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

# TYPE_NEW   
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

        self.backward_call_stack = []  # backward
        self.backward_call_paths = []  # backward
        self.collected_backward_callsites = []  # callsite
        self.already_processed_backward_callsite = set()  # 
        self.nodeid_to_callname_cache = dict()  # nodeid  callname 
        

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
        """"""            
        for new_path in new_paths:
            for existing_path in old_paths:
                if self._paths_equal(existing_path, new_path):
                    return True
        return False
    
    def _paths_equal(self, path1, path2):
        """"""
        if len(path1) != len(path2):
            return False
        
        #  call_site_id 
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
        #  pickle  self.all_paths
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
        
        `paths` 
        - (list[dict])
        - (list[list[dict]])
         dict 
        - call_site_code
        - direction: 'caller'  'callee'
        - depth (callee ) / level (caller )
        - callee_name
        - location: {'file': ..., 'line': ...}
        - param_pos / marker 
        """

        # list[dict] list[list[dict]]
        if paths and isinstance(paths[0], dict):
            all_paths = [paths]
        else:
            all_paths = paths

        print(f"\n===  {len(all_paths)}  ===\n")

        for idx, path in enumerate(all_paths, 1):
            print(f" {idx}:")
            if not path:
                print("  ()\n")
                continue

            #  caller / callee 
            caller_len = sum(1 for c in path if c.get("direction") == "caller")
            callee_len = sum(1 for c in path if c.get("direction") == "callee")

            segment = None  # 'caller'  'callee'
            caller_idx = 0
            callee_idx = 0

            for call in path:
                curr = call.get("direction", "callee")  #  callee
                if curr not in ("caller", "callee"):
                    curr = "callee"

                # 
                if curr != segment:
                    segment = curr
                    header = "↑ Caller " if segment == "caller" else "↓ Callee "
                    print(f"  {header}")

                # 
                if segment == "caller":
                    # caller 
                    indent_level = max(0, (caller_len - 1 - caller_idx))
                else:
                    # callee 
                    #  depth  callee_idx
                    indent_level = call.get("depth", callee_idx)

                indent = "    " * indent_level

                # tag
                if segment == "caller":
                    lvl = call.get("level", caller_idx)
                    tag = f"Caller L{lvl}"
                    name = call.get("caller_name", "<unknown_caller>")
                else:
                    depth = call.get("depth", callee_idx)
                    tag = f"Callee D{depth}"
                    name = call.get("callee_name", "<unknown_callee>")

                code = call.get("call_site_code", "<unknown_call_site>")

                # 
                print(f"{indent}[{tag}] {code}")

                #  callee_name
                marker = call.get("marker")
                marker_str = f" [: {marker}]" if marker else ""
                param_pos = call.get("param_pos")
                if param_pos is not None and param_pos >= 0:
                    param_str = f"param_pos={param_pos}"
                else:
                    param_str = ""

                if segment == "caller":
                    direction_text = ""
                else:
                    direction_text = ""

                extra = ", ".join(x for x in [param_str] if x)
                extra = f" ({extra})" if extra else ""

                print(f"{indent}  └─> {direction_text} {name}{extra}{marker_str}")

                # 
                loc = call.get("location")
                if isinstance(loc, dict):
                    print(f"{indent}      @ {loc.get('file', '?')}:{loc.get('line', '?')}")

                # 
                if segment == "caller":
                    caller_idx += 1
                else:
                    callee_idx += 1

            print()  # 


    def print_potential_source_funcname(self):
        """ source """
        print(f"\n===  {len(self.potential_source_funcname)}  source  ===\n")
        for funcname in self.potential_source_funcname:
            print(f"- {funcname}")
        print()

    def print_builtin_sources(self):
        """ source """
        print(f"\n===  {len(self.sources)}  source  ===\n")
        for src in self.sources:
            print(f"- ID: {src}")
        print()


    
    def find_function_arg_node_list_1127(self, node):
        if node[NODE_TYPE] not in [TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL, TYPE_NEW, TYPE_ECHO, TYPE_PRINT, TYPE_INCLUDE_OR_EVAL, TYPE_EXIT, TYPE_FUNC_DECL, TYPE_METHOD, TYPE_RETURN, TYPE_EMPTY]:
            print(f"[-] Warning: Node {node[NODE_INDEX]} is not a function/method call or declaration.")
            return "()"
        arg_str = "("
        #  arg_list
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
        #  patch  sink
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

            self.do_backward_slice()        #  callsite


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
         cve_id +  + commit + sink_nodeid 
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

        self.do_backward_slice()        #  callsite


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
         cve_id +  + commit + sink_nodeid 
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

        self.do_backward_slice()        #  callsite

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
    #     self.far_node = min(self.pdg_digraph.nodes.keys())  #  node
    #     self.taint_param = taint_param

    def do_backward_slice(self):
        """backward slice"""
        # self.__backup_anchor_node_id = self.anchor_node.node_id
        taint_param = None
        taint_param_pos = -1
        if self.anchor_node_ast is None:
            self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
        
        
        # rule1  
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
        
        #  anchor 
        # self.sink_func_node = self.analyzer.basic_step.get_node_itself(
        #     self.anchor_node_ast[NODE_FUNCID]
        # )
        
        #  patch backward slicedepth=0, level=0 sink backward  patch
        self._do_backward_slice_interprocedural(
            self.anchor_node_ast, 
            pdg_parent=None, 
            id_threshold=self.anchor_node_ast[NODE_INDEX],
            taint_param=taint_param,
            depth=0,  # callee
            level=0   # caller
        )
        
        self.far_node = min(self.pdg_digraph.nodes.keys()) if self.pdg_digraph.nodes else None
        self.taint_param = taint_param

        self._pop_backward_call_stack()
        
        # callsite
        self._print_backward_analysis_results()

        self.backward_call_stack.clear()
        self.anchor_node_ast = None
        self.anchor_node_root = None

    def _do_backward_slice_interprocedural(self, node, pdg_parent=None, id_threshold=0xff, taint_param=None,
                                    depth=0, level=0):
        """
        backward slice
        
        Args:
            node: 
            pdg_parent: PDG
            id_threshold: 
            taint_param: 
            depth: callee
            level: caller
        """
        if node is None:
            return
        
        # 
        if depth > self.max_callee_direction_depth:
            self._record_backward_path()
            return
        
        # if node[NODE_INDEX] > id_threshold:
        #     return
        
        # CFG
        if not self.analyzer.cfg_step.has_cfg(node):
            node = self.analyzer.ast_step.get_root_node(node)
            if node[NODE_TYPE] in {TYPE_IF, TYPE_IF_ELEM, TYPE_WHILE, TYPE_DO_WHILE}:
                node = self.analyzer.get_control_node_condition(node)
        
        # PDG
        self.pdg_digraph.add_node(
            node[NODE_INDEX], 
            add_rels="PDG", 
            root_node_id=node[NODE_INDEX], 
            lineno=node[NODE_LINENO],
        )
        
        # TODO: source   source
        global_vars = self.analyzer.ast_step.find_sources(node)
        if global_vars:
            self.sources.add(node[NODE_INDEX])
            add_source_count = 0
            for gvar in global_vars:
                if gvar[NODE_TYPE] == TYPE_DIM:
                    self._push_backward_call_stack(gvar, gvar, "SOURCE", "SOURCE", -1, depth)
                    add_source_count += 1
            self._record_backward_path()  # source
            for i in range(add_source_count):
                self._pop_backward_call_stack()
            return  # source
        
        # PDG
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
                return  # 
        
        # call - callee
        # if node[NODE_TYPE] in {TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
        #     self._handle_backward_call_node(node, taint_param, depth, level, id_threshold)
        calleesite_nodes = self.analyzer.ast_step.filter_child_nodes(node, node_type_filter=COMMON_NODE_TYPES)
        if calleesite_nodes:
            for calleesite_node in calleesite_nodes:
                # 
                if calleesite_node[NODE_INDEX] in [self.anchor_node.node_id, node[NODE_INDEX]]:
                    continue
                self._handle_backward_call_node(calleesite_node, taint_param=taint_param, depth=depth, level=level+1)
        
        # 
        def_nodes = self.analyzer.pdg_step.find_def_nodes(node)
        if node in def_nodes:
            def_nodes.remove(node)
        
        # 
        param_nodes = self._check_data_from_params(node, def_nodes, taint_param)
        
        # caller callee          # caller
        if param_nodes and level < self.max_caller_direction_level:  
            taint_param = param_nodes[0]['taint_var']
            self._analyze_caller_functions(node, param_nodes, taint_param, depth, level)
        
        # backward slice
        for def_node in def_nodes:
            if def_node is None or def_node[NODE_INDEX] > id_threshold:
                continue
            # if 'taint_var' in def_node:
            #     def_node_var_name = "$" + def_node['taint_var']
            #     if taint_param:
            #         if def_node_var_name != taint_param:
            #             continue

            # 
            var_rels = self.analyzer.neo4j_graph.relationships.match(
                [def_node, node], r_type=DATA_FLOW_EDGE
            )
            # current_taint = set(taint_param) if taint_param else set()
            
            for rel in var_rels:
                if 'var' in rel:
                    current_taint = '$' + rel['var']
            # current_taint = var_rels[0]['var']
            
            # backward slice
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
            #  $this->method()  
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
                    #  var call
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
                    # 
                    # $this->di['db']->getCell($sql , $values);   $di['request']->getClientAddress(), 
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
                    #  code
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
            #  code
            method_call_name = self.analyzer.code_step.get_node_code(node)
        return method_call_name

    # TODO:   
    def _handle_backward_call_node(self, call_node, taint_param, depth, level):
        """
        backwardcall
        callee
        """
        # callsite
        # method name  funcname
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
        
        #    processed  call chain. processed  push 
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
        
        # 
        call_hash = f"{call_node[NODE_INDEX]}_{func_decl[NODE_INDEX]}"
        if call_hash in self.already_processed_backward_callsite:
            return
        self.already_processed_backward_callsite.add(call_hash)

        
        func_name = call_node_name
        if func_name == "build_graph_object_sql_having":
            print("db")
        node_hash = f"{func_decl[NODE_INDEX]}::{func_name}"
        self.__cache_center.update_already_detect_functions(node_hash, 1)
        
        # 
        self._push_backward_call_stack(
            call_node, func_decl, "return_value", taint_param, args_pos, depth
        )
        
        # return
        depth += 1
        if depth <= self.max_callee_direction_depth:
            self._analyze_callee_returns(func_decl, call_node, taint_param, depth, level)
        else:
            self._record_backward_path()
        # 
        self._pop_backward_call_stack()


    def _analyze_callee_returns(self, func_decl, call_node, taint_param, depth, level):
        """
        return
        returnbackward slice
        """
        # return
        return_nodes = self.analyzer.ast_step.filter_child_nodes(
            func_decl, node_type_filter=[TYPE_RETURN]
        )
        
        for return_node in return_nodes:
            # return
            return_root = self.analyzer.ast_step.get_root_node(return_node)
            
            # returnbackward slice
            # id_thresholdreturnindex
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
        
        
        """
        param_nodes = []
        
        for def_node in def_nodes:
            if def_node[NODE_TYPE] == TYPE_PARAM:
                param_nodes.append(def_node)
        
        return param_nodes


    def _analyze_caller_functions(self, param_use_node, param_nodes, taint_param, depth, level):
        """
        caller
        TODO: 
        Args:
            param_use_node: 
            param_nodes: 
            taint_param: 
            depth: callee
            level: caller
        """
        if level >= self.max_caller_direction_level:  # caller
            self._record_backward_path()
            return
        
        # 
        current_func = self.analyzer.basic_step.get_node_itself(
            param_use_node[NODE_FUNCID]
        )
        
        if current_func is None:
            return
        
        # call site
        call_sites = self.analyzer.cg_step.find_call_nodes(current_func)
        
        if not call_sites:
            self._record_backward_path()
            return
        
        if len(call_sites) > 5:  # 
            call_sites = call_sites[:3]
        
        for param_node in param_nodes:
            param_position = param_node[NODE_CHILDNUM]  # 
            
            for call_site in call_sites:
                # 
                call_hash = f"{call_site[NODE_INDEX]}_{current_func[NODE_INDEX]}"
                if call_hash in self.already_processed_backward_callsite:
                    continue
                self.already_processed_backward_callsite.add(call_hash)
                
                if call_site[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL}:
                    call_site_name = self.get_method_call_name(call_site)
                else:
                    call_site_name = self.analyzer.code_step.get_node_code(call_site)

                # callsite
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
                
                # caller
                caller_func = self.analyzer.basic_step.get_node_itself(
                    call_site[NODE_FUNCID]
                )
                
                # TODO: call site   arg list 
                taint_arg = None
                args_list = self.analyzer.ast_step.find_function_arg_node_list(call_site)
                for arg_name, arg_pos in args_list.items():
                    if arg_pos == param_position:
                        taint_arg = arg_name
                        break

                matching_arg_node = None
                #  callsite
                # for arg_name, arg_pos in args_list.items():
                #     if arg_pos == param_position:
                #         # AST
                #         arg_nodes = self.analyzer.ast_step.filter_child_nodes(
                #             call_site, node_type_filter=VAR_TYPES_EXCLUDE_CONST_VAR
                #         )
                #         for arg_node in arg_nodes:
                #             if arg_node[NODE_CHILDNUM] == param_position:
                #                 matching_arg_node = arg_node
                #                 break
                #         break
                #  taint var  caller 
                if matching_arg_node is None:
                    # call_site
                    matching_arg_node = self.analyzer.ast_step.get_root_node(call_site)
                
                # caller
                self._push_backward_caller_stack(
                    call_site, caller_func, param_node, taint_param, param_position, level
                )
                
                # callerbackward slice
                new_level = level + 1   # 
                # call_site_root = self.analyzer.ast_step.get_root_node(call_site)
                
                self._do_backward_slice_interprocedural(
                    matching_arg_node,
                    pdg_parent=None,
                    id_threshold=matching_arg_node[NODE_INDEX],
                    taint_param=taint_arg,
                    depth=0,  # depthcaller
                    level=new_level
                )
                
                # caller
                self._pop_backward_caller_stack() 


    # =====  =====

    def _push_backward_call_stack(self, call_site, callee_func, marker, taint_param, param_pos, depth):
        """backward callee"""
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
        """backward caller"""
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
        """backward"""
        if self.backward_call_stack:
            self.backward_call_stack.pop()


    def _pop_backward_caller_stack(self):
        """backward caller"""
        if self.backward_call_stack:
            self.backward_call_stack.pop()


    def _record_backward_path(self):
        """backward"""
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
        
        #   
        if not self._is_duplicate_backward_path(path):
            self.backward_call_paths.append(path)


    def _is_duplicate_backward_path(self, new_path):
        """backward"""
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
        """"""
        file_name = self.analyzer.fig_step.get_belong_file(node)
        
        return {
            'file': file_name,
            'line': node[NODE_LINENO] if NODE_LINENO in node else 'unknown'
        }


    def _print_backward_analysis_results(self):
        """backward"""
        print("\n" + "="*80)
        print("Backward Slice Analysis Results")
        print("="*80)
        
        print(f"\n[*] Total collected callsites: {len(self.collected_backward_callsites)}")
        print(f"[*] Total backward paths: {len(self.backward_call_paths)}")
        print(f"[*] Sources found: {len(self.sources)}")
        
        # 
        callee_callsites = [c for c in self.collected_backward_callsites if c['direction'] == 'callee']
        caller_callsites = [c for c in self.collected_backward_callsites if c['direction'] == 'caller']
        
        print(f"\n[*] Callee direction callsites: {len(callee_callsites)}")
        print(f"[*] Caller direction callsites: {len(caller_callsites)}")
        
        # callsite
        print("\n" + "-"*80)
        print("Collected Callsites:")
        print("-"*80)
        
        for i, callsite in enumerate(self.collected_backward_callsites, 0):
            print(f"\n[{i}] {callsite['direction'].upper()} direction (depth={callsite['depth']}, level={callsite['level']})")
            print(f"    Code: {callsite['code']}")
            print(f"    Location: {callsite['location']['file']}:{callsite['location']['line']}")
            if 'param_position' in callsite:
                print(f"    Parameter position: {callsite['param_position']}")
        
        # 
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
    
    #  find source x slice  slice 
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
    #         self.sources.add(node[NODE_INDEX])  #  nodefind_source childnode  assign assign 
        
    #     if pdg_parent is not None:
    #         assert taint_param is not None
    #         if self.pdg_digraph.has_edge(node[NODE_INDEX], pdg_parent[NODE_INDEX]):
    #             return
    #         else:
    #             self.pdg_digraph.add_edge(
    #                 node[NODE_INDEX], pdg_parent[NODE_INDEX], add_rels='PDG', taint_param=taint_param
    #             )
        
    #     #  node 
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

    # add:  source 
    def do_forward_path_exploration(self):
        potential_condition_nodes = [i for i, in self.analyzer.run(
            "MATCH (A:AST) - [:PARENT_OF] -> (B:AST) WHERE A.type='AST_IF_ELEM' AND B.childnum=0 " + \
            f"AND B.type <> 'NULL' AND {self.far_node - 100} <= B.id AND B.id <= {self.far_node} RETURN B"
        )]      #  far  check check  far_node  far_node  sink_node 
        condition_ids = set()
        for node in potential_condition_nodes:
            parent_node = self.analyzer.get_ast_parent_node(node)
            low_bound, high_bound = self.analyzer.range_step.get_condition_range(parent_node)
            if low_bound <= self.far_node and self.far_node <= high_bound and \
                    (self.analyzer.ast_step.find_sources(node) or self.analyzer.ast_step.find_custom_sources(node, self.custom_sources)):  #  check  global var condition  global  condition_ids check 
                condition_ids.add(node[NODE_INDEX])
        
        far_node_ast = self.analyzer.get_node_itself(self.far_node)

        if self.anchor_node_root[NODE_INDEX] == far_node_ast[NODE_INDEX]:
            self.context_series.append(([self.anchor_node.node_id], sorted(condition_ids)))
            return

        self._do_forward_path_exploration(node=far_node_ast, cfg_pdg_path=set(), path_conditions=condition_ids,  
                                          threshold=[far_node_ast[NODE_INDEX], self.anchor_node_ast[NODE_INDEX]],
                                          cycle_exit_identifier=set())  # range  far_node  sink_node 

    def _do_forward_path_exploration(self, node: py2neo.Node, cfg_pdg_path: set = set(), path_conditions: set = set(),
                                     has_source=False, threshold=None, cycle_exit_identifier: set = None, **kwargs):
        #  source 
        # forward  

        if self.sources.__len__() == 0:
            return None
        
        if cycle_exit_identifier is None:
            cycle_exit_identifier = {(-0xcaff, -0xcaff)}
        if threshold is None:
            threshold = [-0xff, 0xffff]
        threshold_bottom, threshold_upper = threshold
        #  farnode  farward exploration
        if node is None or node.labels.__str__() != ":" + LABEL_AST:
            return None
        if node[NODE_INDEX] < threshold_bottom or node[NODE_INDEX] > threshold_upper:
            return None
        #  node 
        node = self._find_outside_exit_identifier(cycle_exit_identifier, node)
        if node[NODE_LINENO] is None:
            return None

        if node[NODE_INDEX] in self.pdg_digraph.nodes.keys():   #  cfg_pdg_path 
            cfg_pdg_path.add(node[NODE_INDEX])
            if node[NODE_INDEX] in self.sources:
                has_source = True

        #   node  sink sink forward exploration 
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
                                                  threshold=[-1, threshold_upper]) # cfg_rels[0]  true cfg_rels[0].end_node 
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                #  reaches*1..  source 
                # MATCH (S:AST {id: 273}), (C:AST {id: 297})
                # MATCH P = shortestPath((S)-[:REACHES*1..]->(C))
                # RETURN P
                # shortestPath 

                # source_rels = [i for i, in self.analyzer.run(
                #     f"MATCH P = (S:AST) - [:REACHES*1..] -> (C:AST) WHERE S.id in {list(self.sources).__str__()} " + \
                #     f"AND C.id={node[NODE_INDEX]} RETURN P"
                # )]  #  source  def  condition node  
                
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
    #  taint_param taint_param 
    def do_find_extend_source(self):
        #  self.pdg_digraph 
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

            #  var   ()
            # TODO  mystique  edge  def 
            #  def reach  def
            taint_var_def_nodes = set()
            for taint_var_node in taint_var_nodes:
                def_nodes = self.analyzer.pdg_step.find_def_nodes(taint_var_node)
                if def_nodes.__len__() == 0:
                    taint_var_def_nodes.add(taint_var_node)

            
            for taint_var_def_node in taint_var_def_nodes:
                taint_var_def_node_root = self.analyzer.ast_step.get_root_node(taint_var_def_node)
                taint_var_def_node_roots.add(taint_var_def_node_root)


        # 
        #  ast_call  prompt 
        unique_taint_var_def_node_roots = set()
        unique_callsite_names = set()
        for taint_var_def_node_root in list(taint_var_def_node_roots):
            if taint_var_def_node_root[NODE_TYPE] == TYPE_CALL:
                # TODO  type_call name_child  filter_child_nodes
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
        #  var_def_codes LLM sourcesource 


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


        #  answer  list
        if answer.startswith("[") and answer.endswith("]"):
            items = answer[1:-1].split(",")
            for item in items:
                item = item.strip().strip("'").strip('"')
                if item:
                    self.custom_sources.add(item)
        print("Custom Sources List:", self.custom_sources)


        #  pdg_digraph node  code  custom_sources  sources 
        for node_id in self.pdg_digraph.nodes.keys():
            node = self.analyzer.get_node_itself(node_id)
            if self.analyzer.ast_step.find_custom_sources(node, self.custom_sources):
                self.sources.add(node_id)

        #  source forward  source 

        #  backward_slice 
        #  find_source ()

        #  callsite 