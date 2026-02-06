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
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from collections import defaultdict
import subprocess
import time
import signal

logger = logging.getLogger(__name__)
STORAGE_PATH = f"./detection_storage/"
COMMON_NODE_TYPES = [
        TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL,
        TYPE_INCLUDE_OR_EVAL,
        TYPE_ECHO, TYPE_PRINT, TYPE_EXIT
]

FUNCTION_MODEL = {
        7: ["include", "require", "include_once", "require_once"],
        2: ["file", "file_get_contents", "readfile", "fopen"],
        1: ["unlink", "rmdir"],
        12: ["file_put_contents", "fopen", "fwrite"],
        10: ["echo", "print", "print_r", "die"],
        4: ["exec", "passthru", "proc_open", "system", "shell_exec", "popen", "pcntl_exec"],
        3: ["eval", 'create_function', 'assert'],
        6: ["copy", "fopen", "move_uploaded_file", "rename"],
        # 13: ["header", ],
        8: ["unserialize", ],
        9: ["pg_query", "pg_send_query", "pg_prepare", "mysql_query", "mysqli_prepare", "mysqli_query",
            "mysqli_real_query"]
}

DATABASE_PATH = "../"
def start_database_with_port(db_name, database_path=DATABASE_PATH):
    db_path = os.path.join(database_path, db_name)
    
    if not os.path.exists(db_path):
        print(f"[!] Database path {db_path} does not exist.")
        return False
    
    result = subprocess.run(
        [f"{db_path}/bin/neo4j", "status"],
        capture_output=True,
        text=True,
        check=False
    )
    
    if result.returncode == 0:
        output = result.stdout.strip().lower()
        if "is running at" in output:
            print(f"[*] {db_name} is already running.")
            return True
    
    print(f"[*] Starting database {db_name}...")
    subprocess.run(
        [f"{db_path}/bin/neo4j", "start"],
        capture_output=True,
        text=True,
        check=False
    )
    
    time.sleep(10)
    
    for attempt in range(5):
        result = subprocess.run(
            [f"{db_path}/bin/neo4j", "status"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0 and "is running at" in result.stdout.strip().lower():
            print(f"[+] {db_name} started successfully")
            return True
        time.sleep(2)
    
    print(f"[!] Failed to start {db_name}")
    return False


def stop_database_with_port(db_name, database_path=DATABASE_PATH):
    db_path = os.path.join(database_path, db_name)
    
    if not os.path.exists(db_path):
        return
    
    print(f"[*] Stopping database {db_name}...")
    subprocess.run(
        [f"{db_path}/bin/neo4j", "stop"],
        capture_output=True,
        text=True,
        check=False
    )
    time.sleep(3)


def kill_listen_pid_by_port(port: int, sig=signal.SIGKILL) -> bool:
    cmd = ["lsof", "-nP", "-t", "-i", f":{port}", "-sTCP:LISTEN"]
    r = subprocess.run(cmd, capture_output=True, text=True)

    if r.returncode != 0:
        err = (r.stderr or "").strip()
        if err:
            print(f"[!] lsof error on port {port}: {err}")
        else:
            print(f"[!] No LISTEN process found on port {port}")
        return False

    pids = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if line.isdigit():
            pids.append(int(line))

    if not pids:
        print(f"[!] No LISTEN pid parsed on port {port}")
        return False

    killed_any = False
    for pid in sorted(set(pids)):
        try:
            os.kill(pid, sig) 
            print(f"[+] Killed pid {pid} listening on :{port}")
            killed_any = True
        except ProcessLookupError:
            print(f"[!] pid {pid} not found (already exited)")
        except PermissionError:
            print(f"[!] Permission denied killing pid {pid} (need sudo / same user?)")
        except Exception as e:
            print(f"[!] Failed to kill pid {pid}: {e}")

    return killed_any


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
        if node_type  == 'AST_METHOD_CALL':
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
                    method_call_name = self.analyzer.code_step.get_node_code(node)

        elif node_type == 'AST_STATIC_CALL':
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
        if node[NODE_TYPE] in {TYPE_METHOD_CALL, TYPE_STATIC_CALL, TYPE_CALL}:
            code = self.get_method_call_name(node)
            if not code:
                code = self.analyzer.code_step.get_node_code(node)   
            # print(f"Method/Static/Func Call analyzed code: {code}")
        else:
            code = self.analyzer.code_step.get_node_code(node)
        for vuln_type, anchor_functions in FUNCTION_MODEL.items():
            if code in anchor_functions or f"{code}()" in anchor_functions:
                if code == "fopen" and vuln_type == 2:
                    self.f_insert(node, 12)
                    self.f_insert(node, 6)
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

        if nodes_todo_analysis.__len__() > 30000:
            return
        with ThreadPoolExecutor(max_workers=24) as executor:
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


def process_node_batch_with_db(node_ids, bolt_port, http_port, original_db_name, 
                                target, extend_vuln_model, sink_file,
                                DATABASE_PATH, base_bolt_port):
    import subprocess
    import time
    from collections import defaultdict
    
    db_name = f"{original_db_name}"
    db_path = os.path.join(DATABASE_PATH, db_name)
    # print(f"***************************[Worker-{bolt_port}] Database path: {db_path}****************************")
    
    result_sinks = defaultdict(list)
    
    try:
        # 启动数据库
        print(f"[Worker-{bolt_port}] Starting database {db_name}...")
        # subprocess.run(
        #     [f"{db_path}/bin/neo4j", "start"],
        #     capture_output=True,
        #     text=True,
        #     check=False
        # )
        # time.sleep(10)
        start_database_with_port(db_name, DATABASE_PATH)


        # result = subprocess.run(
        #     [f"{db_path}/bin/neo4j", "status"],
        #     capture_output=True,
        #     text=True,
        #     check=False
        # )
        # if result.returncode != 0:
        #     print(f"{db_name} is not running.")
        #     return result_sinks
        # else:
        #     output = result.stdout.strip().lower()
        #     # if "is running at" in output:
        #     #     print(f"{db_name}: {output}")
        #     pass

        
        config_dict = {
            "all_prepatch": {
                "NEO4J_HOST": "localhost",
                "NEO4J_PORT": bolt_port,
                "NEO4J_USERNAME": "neo4j",
                "NEO4J_PASSWORD": "password",
                "NEO4J_DATABASE": "neo4j",
                "NEO4J_PROTOCOL": "bolt"
            }
        }
        # analyzer = Neo4jEngine.from_dict(config_dict["all_prepatch"])
        while True:
            try:
                analyzer = Neo4jEngine.from_dict(config_dict["all_prepatch"])
                break
            except Exception as e:
                time.sleep(3)

        print(f"[Worker-{bolt_port}] Connected to expected database instance.")

        sink_finder = TargetSinkFinder(
            analysis_framework=analyzer,
            git_repository=target
        )

        query = f"MATCH (n:AST) WHERE id(n) in {node_ids} RETURN n"
        nodes = [node for node, in analyzer.basic_step.run(query)]
        
        for node in tqdm(nodes):
            try:
                flag, vuln_type = sink_finder._anchor_function_analysis(node)
                if flag == 0b10:
                    anchor_node = AnchorNode.from_node_instance(
                        node,
                        judge_type=0b0001,
                        git_repository=target,
                        func_name=analyzer.code_step.get_node_code(node),
                        param_loc=-1,
                        file_name=analyzer.fig_step.get_belong_file_wofileid(node)
                    )
                    result_sinks[vuln_type].append({
                        'node_id': node.identity,
                        'anchor_node': anchor_node
                    })
                    
                    code = analyzer.code_step.get_node_code(node)
                    if code == "fopen" and vuln_type == 2:
                        for extra_type in [12, 6]:
                            anchor_node_extra = AnchorNode.from_node_instance(
                                node,
                                judge_type=0b0001,
                                git_repository=target,
                                func_name=code,
                                param_loc=-1,
                                file_name=analyzer.fig_step.get_belong_file_wofileid(node)
                            )
                            result_sinks[extra_type].append({
                                'node_id': node.identity,
                                'anchor_node': anchor_node_extra
                            })
            except Exception as e:
                logger.error(f"[Worker-{bolt_port}] Error processing node {node.identity}: {e}")
        
        print(f"[Worker-{bolt_port}] Found {sum(len(v) for v in result_sinks.values())} sink nodes")
        
    except Exception as e:
        print(f"[Worker-{bolt_port}] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # print(f"[Worker-{bolt_port}] Stopping database {db_name}...")
        # subprocess.run(
        #     [f"{db_path}/bin/neo4j", "stop"],
        #     capture_output=True,
        #     text=True,
        #     check=False
        # )
        # time.sleep(3)
        print(f"[Worker-{bolt_port}] Finished processing.")
    
    return result_sinks


def cc_run_parallel(original_db_name, target, extend_vuln_model, sink_file, 
                   num_workers, num_neo4j_instances, DATABASE_PATH, base_bolt_port=17687, base_http_port=17474):

    analysis_file_scope_dict = {}                                                       

    first_bolt_port = base_bolt_port
    first_http_port = base_http_port
    first_db_name = f"{original_db_name}"
    pure_db_name = original_db_name.replace("_prepatch", "")
    if pure_db_name in analysis_file_scope_dict:
        sink_file = analysis_file_scope_dict[pure_db_name]
    
    import subprocess
    import time
    db_path = os.path.join(DATABASE_PATH, first_db_name)
    subprocess.run([f"{db_path}/bin/neo4j", "start"], capture_output=True, text=True, check=False)
    print(db_path)
    status = start_database_with_port(first_db_name, DATABASE_PATH)
    time.sleep(10)
    if status is False:
        print("[-] Failed to start first database")
        return defaultdict(AnchorNodeList)
    
    config_dict = {
        "all_prepatch": {
            "NEO4J_HOST": "localhost",
            "NEO4J_PORT": first_bolt_port,
            "NEO4J_USERNAME": "neo4j",
            "NEO4J_PASSWORD": "password",
            "NEO4J_DATABASE": "neo4j",
            "NEO4J_PROTOCOL": "bolt"
        }
    }

    while True:
        try:
            analyzer = Neo4jEngine.from_dict(config_dict["all_prepatch"])
            break
        except Exception as e:
            time.sleep(3)
    # analyzer = Neo4jEngine.from_dict(config_dict["all_prepatch"])
    
    query = f"MATCH (tp: AST) WHERE tp.type = '{TYPE_TOPLEVEL.__str__()}' RETURN tp.fileid, tp.name"
    fileid_name_list = [(fileid, name) for fileid, name in analyzer.basic_step.run(query)]

    fileid_name_dict = {}
    for fileid, name in fileid_name_list:
        if name is None:
            continue
        name_split = name.split("/")
        # if 'vendor' in name_split or 'tests' in name_split or 'test' in name_split:# or 'lib' in name_split:
        #     continue
        if fileid not in fileid_name_dict:
            fileid_name_dict[fileid] = name
    
    fileid_list = list(fileid_name_dict.keys())
    print(f"Total files to analyze: {len(fileid_list)}")
    
    if sink_file is not None:
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
    
    query = f"MATCH (n:AST) WHERE n.type in {COMMON_NODE_TYPES.__str__()} and n.fileid in {fileid_list} RETURN id(n)"
    node_ids = [node_id for node_id, in analyzer.basic_step.run(query)]
    print(f"Total nodes to analyze: {len(node_ids)}")
    
    if len(node_ids) > 110000:
        # subprocess.run([f"{db_path}/bin/neo4j", "stop"], capture_output=True, text=True, check=False)
        stop_database_with_port(first_db_name, DATABASE_PATH)
        return defaultdict(AnchorNodeList)
    

    for vuln_type in extend_vuln_model:
        if vuln_type in FUNCTION_MODEL:
            FUNCTION_MODEL[vuln_type] = list(set(FUNCTION_MODEL[vuln_type] + extend_vuln_model[vuln_type]))

        else:
            FUNCTION_MODEL[vuln_type] = extend_vuln_model[vuln_type]
    batch_size = len(node_ids) // num_workers + 1
    node_id_batches = [node_ids[i:i + batch_size] for i in range(0, len(node_ids), batch_size)]


    print("============================")
    print(f"Step 2: use {num_neo4j_instances} 个数据库 {num_workers} 个 worker 并行分析节点...")
    print(f"每个worker处理约 {batch_size} 个节点")
    print("============================")

    steps = num_workers // num_neo4j_instances + 1
    all_results = []
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for i, batch in enumerate(node_id_batches):
            if not batch:
                continue
            # bolt_port = base_bolt_port + i
            # http_port = base_http_port + i
            # bolt_port = base_bolt_port + (i // steps)
            # http_port = base_http_port + (i // steps)
            bolt_port = base_bolt_port
            http_port = base_http_port
            
            future = executor.submit(
                process_node_batch_with_db,
                batch, bolt_port, http_port, original_db_name,
                target, extend_vuln_model, sink_file,
                DATABASE_PATH, base_bolt_port
            )
            futures.append(future)
        
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing batches"):
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                print(f"Error in worker: {e}")
                import traceback
                traceback.print_exc()
    
    
    merged_sinks = defaultdict(AnchorNodeList)
    for result in all_results:
        for vuln_type, sink_list in result.items():
            for sink_info in sink_list:
                merged_sinks[vuln_type].add_without_check(sink_info['anchor_node'])
    
    total_sinks = sum(len(sinks) for sinks in merged_sinks.values())
    print(f"\nFound Sink nodes statistics:")
    for vuln_type, sinks in merged_sinks.items():
        if sinks:
            vuln_name = {
                1: 'File_Delete', 2: 'File_Read', 3: 'Code_Injection',
                4: 'Command_Injection', 6: 'File_Upload', 7: 'File_Include',
                9: 'SQL_Injection', 10: 'XSS', 12: 'File_Write'
            }.get(vuln_type, f'Type_{vuln_type}')
            print(f"  {vuln_name}: {len(sinks)} nodes")
    print(f"Total: {total_sinks} sink nodes\n")
    
    return merged_sinks