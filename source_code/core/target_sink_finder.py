import logging
from platform import node
from typing import Set
import py2neo
import os
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from core.anchor_node import AnchorNode
from config import STORAGE_PATH
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from collections import defaultdict

logger = logging.getLogger(__name__)

COMMON_NODE_TYPES = [
        TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL,
        TYPE_INCLUDE_OR_EVAL,
        TYPE_ECHO, TYPE_PRINT, TYPE_EXIT
]

# FUNCTION_MODEL = {
#         7: ["include", "require", "include_once", "require_once"],
#         2: ["file", "file_get_contents", "readfile", "fopen"],
#         1: ["unlink", "rmdir"],
#         12: ["file_put_contents", "fopen", "fwrite"],
#         10: ["echo", "print", "print_r", "die"],
#         4: ["exec", "passthru", "proc_open", "system", "shell_exec", "popen", "pcntl_exec"],
#         3: ["eval", 'create_function', 'assert', 'array_map', 'preg_replace'],
#         6: ["copy", "fopen", "move_uploaded_file", "rename"],
#         13: ["header", ],
#         8: ["unserialize", ],
#         9: ["pg_query", "pg_send_query", "pg_prepare", "mysql_query", "mysqli_prepare", "mysqli_query",
#             "mysqli_real_query"]
# }
FUNCTION_MODEL = {
        7: ["include", "require", "include_once", "require_once"],
        2: ["file", "file_get_contents", "readfile", "fopen"],
        1: ["unlink", "rmdir"],
        12: ["file_put_contents", "fopen", "fwrite"],
        # 10: ["echo", "print", "print_r", "die"],
        4: ["exec", "passthru", "proc_open", "system", "shell_exec", "popen", "pcntl_exec"],
        3: ["eval", 'create_function', 'assert', 'array_map', 'preg_replace'],
        6: ["copy", "fopen", "move_uploaded_file", "rename"],
        # 13: ["header", ],
        8: ["unserialize", ],
        9: ["pg_query", "pg_send_query", "pg_prepare", "mysql_query", "mysqli_prepare", "mysqli_query",
            "mysqli_real_query"]
}

# class AnchorNodeList(Set):
#     def __init__(self):
#         super(AnchorNodeList, self).__init__()

#     def add(self, __object, analyzer: Neo4jEngine) -> None:
#         _obj_ast = analyzer.basic_step.get_node_itself(__object.node_id)
#         if analyzer.pdg_step.is_tracable(_obj_ast=_obj_ast):
#             super(AnchorNodeList, self).add(__object)

#     def add_without_check(self, __object: AnchorNode):
#         super(AnchorNodeList, self).add(__object)

class AnchorNodeList(set):
    def __init__(self, iterable=None):
        super().__init__(iterable if iterable is not None else [])

    def add(self, __object, analyzer: Neo4jEngine) -> None:
        _obj_ast = analyzer.basic_step.get_node_itself(__object.node_id)
        if analyzer.pdg_step.is_tracable(_obj_ast=_obj_ast):
            super().add(__object)

    def add_without_check(self, __object: AnchorNode):
        super().add(__object)


class TargetSinkFinder(object):
    def __compile_potential_sinks(self):
        for vuln_type in FUNCTION_MODEL.keys():
            self.potential_sinks[vuln_type] = AnchorNodeList()

    def __complie_storage_path(self):
        storage_dir = os.path.join(STORAGE_PATH, "sink_cache")
        if not os.path.exists(storage_dir):
            os.mkdir(storage_dir)
        self.sink_storage_path = os.path.join(storage_dir, f"{self.git_repository}.json")

    def __init__(self, analysis_framework: Neo4jEngine, git_repository, cve_id=None):
        self.analyzer = analysis_framework
        self.git_repository = git_repository
        self.potential_sinks = defaultdict(AnchorNodeList)
        self.__compile_potential_sinks()
        self.__complie_storage_path()

        self._lock = defaultdict(threading.Lock)

    def f_insert(self, n, vuln_type, judge_type=0b0001, loc=-1):
        # try:
        #     self.potential_sinks[vuln_type].add(
        #             AnchorNode.from_node_instance(
        #                     n, judge_type=judge_type, git_repository=self.git_repository,
        #                     func_name=self.analyzer.code_step.get_node_code(n), param_loc=loc,
        #                     file_name=self.analyzer.fig_step.get_belong_file(n)
        #             ), self.analyzer
        #     )
        # except:
        #     pass
        lock = self._lock[vuln_type]
        with lock:
            self.potential_sinks[vuln_type].add(
                AnchorNode.from_node_instance(
                        n, judge_type=judge_type, git_repository=self.git_repository,
                        func_name=self.analyzer.code_step.get_node_code(n), param_loc=loc,
                        file_name=self.analyzer.fig_step.get_belong_file_wofileid(n)
                ), self.analyzer
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
    
        return method_call_name

    def _anchor_function_analysis(self, node: py2neo.Node, TAINT_DYNAMIC_CALL_FLAG: bool = None) -> int:
        if node[NODE_TYPE] in {TYPE_ECHO, TYPE_PRINT}:
            nn = self.analyzer.ast_step.filter_child_nodes(_node=node, node_type_filter=VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL)
            if nn.__len__() >= 1:
                return 0b10, 10
            else:
                return 0b00, -1
        elif node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL} \
                and node[NODE_FLAGS][-1] in \
                {FLAG_EXEC_INCLUDE, FLAG_EXEC_INCLUDE_ONCE, FLAG_EXEC_REQUIRE, FLAG_EXEC_REQUIRE_ONCE}:
            return 0b10, 7
        elif node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL} \
                and node[NODE_FLAGS][-1] in {FLAG_EXEC_EVAL}:
            return 0b10, 4
        code = None
        if node[NODE_TYPE] in {TYPE_METHOD_CALL}:
            # 这里处理几种常见的 method_call 情况，太多的就不管了
            # a->b->func()  |  a->func()
            code = self.get_method_call_name(node)
            if not code:
                code = self.analyzer.code_step.get_node_code(node)   
        else:
            code = self.analyzer.code_step.get_node_code(node)      # AST_STATIC_CALL 的 node code 可以直接获取 AST_METHOD_CALL 只能获取最后一个method名，前面的嵌套的property和method获取不到
        for vuln_type, anchor_functions in FUNCTION_MODEL.items():
            if code in anchor_functions or f"{code}()" in anchor_functions:
                if code == "fopen" and vuln_type == 2:
                    self.f_insert(node, 12)
                    self.f_insert(node, 6)
                # if vuln_type == 9:
                #     print("db")
                return 0b10, vuln_type
        if code in PHP_BUILT_IN_FUNCTIONS and node[NODE_TYPE] == TYPE_CALL:
            return 0b00, -1
        if node[NODE_TYPE] in {TYPE_STATIC_CALL, TYPE_CALL, TYPE_METHOD_CALL}:
            if self.analyzer.cg_step.find_decl_nodes(node):
                return 0b01, -1
            else:
                return 0b00, -1
        return 0b00, -1
    
    def load_sinks(self):
        if os.path.exists(self.sink_storage_path):
            with open(self.sink_storage_path, "r") as f:
                sink_storage = json.load(f)

            for vuln_type, sink_list in sink_storage.items():
                for node_dict in sink_list:
                    node = self.analyzer.get_node_itself(node_dict['id'])
                    self.potential_sinks[vuln_type].add_without_check(
                        AnchorNode.from_node_instance(
                            node, judge_type=node_dict['judge_type'], param_loc=node_dict['loc'],
                            git_repository=self.git_repository,
                            func_name=self.analyzer.code_step.get_node_code(node), 
                            file_name=self.analyzer.fig_step.get_belong_file(node)
                        )
                    )
            return True
        else:
            return False

    def store_sinks(self):
        sink_storage = {}
        for vuln_type in self.potential_sinks:
            if self.potential_sinks[vuln_type]:
                sink_storage[vuln_type] = [
                            {"id": i.node_id, "judge_type": i.judge_type, "loc": i.param_loc[-1]} 
                             for i in self.potential_anchor_nodes[vuln_type]]
        if sink_storage:
            with open(self.sink_storage_path, "w") as f:
                json.dump(obj=sink_storage, fp=f)

    def run(self) -> bool:
        query = f"MATCH (n:AST) WHERE n.type in {COMMON_NODE_TYPES.__str__()} RETURN n"
        nodes_todo_analysis = [node for node, in self.analyzer.basic_step.run(query)]
        for node_todo_analysis in nodes_todo_analysis:
            flag, vuln_type = self._anchor_function_analysis(node_todo_analysis, )
            if flag == 0b00:
                continue
            elif flag == 0b10:
                self.f_insert(node_todo_analysis, vuln_type)
            elif flag == 0b01:
                pass

    def cc_run(self, extend_vuln_model, sink_file=None) -> bool:

        # 这一步太慢了，在testdata 验证的时候太慢了，我决定加个东西，指定在 cve 发生的那个文件中分析。
        # 设定一个开关，在测试集时打开


        # 扩展漏洞模型
        for vuln_type in extend_vuln_model:
            if vuln_type in FUNCTION_MODEL:
                FUNCTION_MODEL[vuln_type].extend(extend_vuln_model[vuln_type])
            else:
                FUNCTION_MODEL[vuln_type] = extend_vuln_model[vuln_type]


        query = f"MATCH (tp: AST) WHERE tp.type = '{TYPE_TOPLEVEL.__str__()}' RETURN tp.fileid, tp.name"
        fileid_name_list = [(fileid, name) for fileid, name in self.analyzer.basic_step.run(query)]

        fileid_name_dict = {}
        for fileid, name in fileid_name_list:
            if name is None:
                continue
            name_split = name.split("/")
            if 'vendor' in name_split or 'tests' in name_split or 'test' in name_split or 'lib' in name_split:
                continue
            if fileid not in fileid_name_dict:
                fileid_name_dict[fileid] = name

        


        fileid_list = list(fileid_name_dict.keys())
        print(f"Total files to analyze: {len(fileid_list)}")


        if sink_file is not None:
            # 只分析给定文件，先遍历 fileid_name_dict，然后判断文件名，取出对应的 fileid
            target_fileids = []
            for fileid, name in fileid_name_dict.items():
                if type(sink_file) == list:
                    for sf in sink_file:
                        if name.endswith(sf):
                            target_fileids.append(fileid)
                elif type(sink_file) == str:
                    if name.endswith(sink_file):
                        target_fileids.append(fileid)
            fileid_list = target_fileids
            print(f"After filtering by sink file, total files to analyze: {len(fileid_list)}")

        query = f"MATCH (n:AST) WHERE n.type in {COMMON_NODE_TYPES.__str__()} and n.fileid in {fileid_list} RETURN n"
        nodes_todo_analysis = [node for node, in self.analyzer.basic_step.run(query)]
        print(f"Total nodes to analyze: {len(nodes_todo_analysis)}")

        if nodes_todo_analysis.__len__() > 50000:
            print("node to analyze 太多了，暂时先不处理。")
            return

        print("============================")
        print("开始分析 sink 节点 ...")
        print("============================")
        with ThreadPoolExecutor(max_workers=18) as executor:
            futures_to_node = {executor.submit(self._anchor_function_analysis, node): node for node in nodes_todo_analysis}
            for future in tqdm(as_completed(futures_to_node), total=len(nodes_todo_analysis)):
                node_todo_analysis = futures_to_node[future]
                try:
                    flag, vuln_type = future.result()
                    if flag == 0b00:
                        continue
                    elif flag == 0b10:
                        self.f_insert(node_todo_analysis, vuln_type)
                    elif flag == 0b01:
                        pass
                except Exception as e:
                    logger.error(f"Error processing node {node_todo_analysis}: {e}")


        # for node_todo_analysis in tqdm(nodes_todo_analysis):
        #         flag, vuln_type = self._anchor_function_analysis(node_todo_analysis)
        #         try:
        #             if flag == 0b00:
        #                 continue
        #             elif flag == 0b10:
        #                 self.f_insert(node_todo_analysis, vuln_type)
        #             elif flag == 0b01:
        #                 pass
        #         except Exception as e:
        #             logger.error(f"Error processing node {node_todo_analysis}: {e}")
