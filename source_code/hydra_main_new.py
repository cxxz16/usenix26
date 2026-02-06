#utf-8 -*-
import json
import os
import copy
import pickle
import time
import traceback
import sys
import logging
import shutil
import subprocess
from typing import List
from datetime import datetime
from core.target_sink_finder import TargetSinkFinder
from core.context_slicer import ContextSlicer
from core.neo4j_connector_center import Neo4jConnectorCenter
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
logger = logging.getLogger(__name__)
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import threading
import queue
import re
import openai
import signal
from core.forward_slice import InterproceduralForwardSlicer
from core.context_slicer_sig import ContextSlicerSig
from core.helper import get_expression_and_conditions
import queue as queue_mod
from multiprocessing import get_context
from concurrent.futures import ProcessPoolExecutor, as_completed, TimeoutError
from multiprocessing import Process, Queue, Manager


API_KEY = [

]



VULN_TYPE_DICT = {
    1: 'File_Delete',
    2: 'File_Read',
    3: 'Code_Injection',
    4: 'Command_Injection',
    6: 'File_Upload',
    7: 'File_Include',
    9: 'SQL_Injection',
    10: 'XSS',
    12: 'File_Write'
}

NEO4J_CONFIGURE_MAP_PATH = "./neo4j.json"
BASE_URL = "https://yunwu.ai/v1"

PORT_POOL = queue.Queue()
PORT_LOCK = threading.Lock()
BASE_BOLT_PORT = 17687
BASE_HTTP_PORT = 17474


def llm_find_potential_source(potential_source_funcname: set, api_key: str, model: str) -> List[str]:
    """API keyLLM"""
    from func_timeout import func_timeout, FunctionTimedOut
    
    try:
        return func_timeout(60, _inner_llm_find_potential_source, 
                          args=(potential_source_funcname, api_key, model))
    except FunctionTimedOut:
        print(f"Timeout with API key {api_key[:8]}... Returning empty.")
        return []


def _inner_llm_find_potential_source(potential_source_funcname: set, api_key: str, model="gpt-5") -> List[str]:
    # TODO  Input::get(page, 1)   
    # return ['get_request_var']
    prompt = """
### Task:
You are a senior PHP expert. Your task is to fully utilize your existing knowledge of PHP frameworks, third-party libraries, and the semantics of the given functions/methods, to carefully determine which ones **retrieve input from the client**, or **serve as wrapper interfaces that extract input** (including HTTP request bodies, query parameters, form fields, headers, cookies, etc.).

### Requirements:
** Three categories to identify **
1. Native or PHP-superglobal based input retrieval
e.g., $_GET, $_POST, $_REQUEST, $_COOKIE, file_get_contents('php://input'), etc.

2. Third-party framework/library request input interfaces
e.g., request()->getBody(), $request->getParams(), $request->getQueryParams(), Symfony Request::get(), Laravel request()->input(), etc.

3. Project-defined wrapper functions/methods for retrieving input
e.g., get_request_var(), appRequest()->get(), wrappers around PHP globals or framework request objects.

** Certain categories to exclude **
1. Functions that do not retrieve client input (pure logic functions, helpers, formatters, validators, internal parsing)
2. ORM/entity operations, database reads, cache reads (not client input)
3. Any function you cannot confidently identify as retrieving client input.  
   If you lack sufficient confidence in a function, do not guess — skip it.

### Input
{call_expr}

### Output Requirements
Please output a list of the methods/functions that meet the criteria, wrapped in an XML tag `<answer>`. Keep your thoughts in mind, but don't show them in the output.
Please return only the function names, without parameters, and separate the function names with commas. For example, After your evaluation, the function calls that meet the conditions are functionA_call(arg1, arg2) and functionB_call(arg1). The final return should be: <answer>['functionA_call', 'functionB_call']</answer>.

### Output 
<answer>[ ]</answer>
"""

    prompt_all_callsite = "\n".join(
            [f"callsite {index + 1}: {code}" for index, code in enumerate(list(potential_source_funcname))]
        )
    prompt = prompt.format(call_expr=prompt_all_callsite)

    # response = openai_chat(prompt, temperature=0.1, model="gpt-5")
    
    client = openai.OpenAI(api_key=api_key, base_url=BASE_URL)
    assis_prompt = """###1 You are an expert in software security with a specialization in secure code auditing. \n###2 Please analyze the information provided by the user and answer the user's question."""
    system_prompt = "You are an expert in software security with a specialization in secure code auditing."
    response = client.chat.completions.create(
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "assistant",
                "content": assis_prompt,
            },
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model=model,
        temperature=0.1,
    )
    response = response.choices[0].message.content
    
    # print("LLM Response:", response)
    # Extract the answer from the response
    if "<answer>" in response and "</answer>" in response:
        answer = response.split("<answer>")[1].split("</answer>")[0].strip()
        print("Extracted Answer:", answer)

    #  answer  list
    #   Input::get(page, 1)  
    custom_sink_funcname_list = set()
    if answer.startswith("[") and answer.endswith("]"):
        items = answer[1:-1].split(",")
        for item in items:
            item = item.split('(')[0].strip().strip("'").strip('"')
            if item:
                custom_sink_funcname_list.add(item)

    return list(custom_sink_funcname_list)





def source_sink_slice_fix_and_merge(source_api, sink_api, code_slices, save_dir, ss_idx, api_key="", model="gpt-5-2025-08-07"):
    prompt = f"""
According to the function call logic, merge the implementations of the following functions into a single function while keeping the semantics unchanged. Additionally, do not write it in a class-based form; convert it into a standalone function implementation.
For functions listed in the source and sink lists, do not expand their implementations — just keep their function calls as they are.

### Note 1: If the PHP file does not contain any classes, you must remove all visibility modifiers (public, protected, private, static) because they are only valid inside classes.
Additionally, for control-flow structures such as if/else, try/catch, and switch/case, you must ensure their syntax is complete. You do not need to fill in the internal logic, but the structure itself must be syntactically valid — for example, if there is a try block, you must also add a corresponding catch block.

### Note 2: Please also pay attention to cross-function argument passing. The actual arguments used in the caller function can be directly moved into the callee instead of keeping them as parameters. For example, if the caller has:
reorder($_POST['a'], $_POST['b']);
and the callee is:
function reorder($table, $next) {{
    $table = $this->Database->escape($table);
}}

it can be converted to:

function reorder() {{
    $table = $_POST['a'];
    $next = $_POST['b'];
    $table = $this->Database->escape($table);
}}


### Note 3: If the source code snippet contains many class members or class methods (identified by keywords such as `self`), convert these references into regular local variables inside the function. Do not keep any class-related markers.

### Note 4: Please double-check for any syntax issues. Make sure the final output is a complete PHP file that can be parsed by a PHP interpreter without any syntax errors.

### Note 5: The `Call Relations` field indicates the call relationship between two adjacent functions. Each element is a tuple, for example (A, B), which means that A calls B.

    # Input
    source function:
    {source_api}
    sink function:
    {sink_api}
    code slices:
    {code_slices}

    # Output
    <ANSWER>
    your answer.
    </ANSWER>
    """

    client = openai.OpenAI(api_key=api_key, base_url=BASE_URL)
    assis_prompt = """###1 You are an expert in software security with a specialization in secure code auditing. \n###2 Please analyze the information provided by the user and answer the user's question."""
    system_prompt = "You are an expert in software security with a specialization in secure code auditing."
    response = client.chat.completions.create(
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "assistant",
                "content": assis_prompt,
            },
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model=model,
        temperature=0.1,
    )
    resp = response.choices[0].message.content

    resp = resp.split("<ANSWER>")[1].split("</ANSWER>")[0].strip()

    if resp.startswith("<?php") is False:
        resp = "<?php\n" + resp
    with open(f"{save_dir}/{ss_idx}.php", "w") as f:
        f.write(resp)

    return resp


def delete_intra_duplicate_slices(all_inter_to_intra_dir):
    """
    
    """
    for vuln_type_dir in os.listdir(all_inter_to_intra_dir):
        vuln_type_path = os.path.join(all_inter_to_intra_dir, vuln_type_dir)
        if not os.path.isdir(vuln_type_path):
            continue

        seen_sinks = set()
        for slice_file in os.listdir(vuln_type_path):
            if "_intra.php" in slice_file:
                sink_id = slice_file.split("src_sink_path_")[-1].split("_")[0]
                if sink_id in seen_sinks:
                    # 
                    os.remove(os.path.join(vuln_type_path, slice_file))
                    print(f"[+] Deleted duplicate intra slice file: {slice_file}")
                else:
                    seen_sinks.add(sink_id)


NEO4J_HOME = f"./detection_projects_neo4j"

# Configuration
PHPJOERN_HOME = ""
def repo_to_neo4j_cpg(repo_dir, repo_name, cpg_project_dir, neo4j_home=None):
    """repoCPGNeo4j"""
    os.environ["HEAP"] = "3G"
    
    neo4j_home = neo4j_home if neo4j_home is not None else NEO4J_HOME
    
    # Neo4j
    if os.path.exists(os.path.join(neo4j_home, repo_name)):
        print(f"[+] cpg & neo4j for {repo_name} already exists. skip cpg generation.")
        return True, None
    
    # CPG
    nodes_path = os.path.join(cpg_project_dir, "nodes.csv")
    rels_path = os.path.join(cpg_project_dir, "rels.csv")
    
    def run_php2ast(file_path, output_nodes, output_rels):
        """php2ast"""
        print(f'[{repo_name}] php2ast is running...')
        result = subprocess.run(
            ["php", 
             "./php2ast/src/Parser.php", 
             "-n", output_nodes,
             "-r", output_rels,
             file_path], 
            cwd=PHPJOERN_HOME,
        )
        if result.returncode != 0:
            print(f"[{repo_name}] php2ast failed with return code: {result.returncode}")
            return False
        
        if not os.path.exists(output_nodes) or not os.path.exists(output_rels):
            print(f"[{repo_name}] nodes.csv or rels.csv not found")
            return False
        
        return True
    
    def run_phpast2cpg(nodes_file, rels_file, output_dir):
        """phpast2cpg"""
        print(f'[{repo_name}] phpast2cpg is running...')
        result = subprocess.run(
            ["java", "-jar", os.path.join(PHPJOERN_HOME, "phpast2cpg.jar"), 
             "-p", os.path.join(PHPJOERN_HOME, "predefined.csv"),
             "-n", nodes_file, 
             "-e", rels_file], 
            cwd=output_dir
        )
        
        if result.returncode != 0:
            print(f"[{repo_name}] phpast2cpg failed with return code: {result.returncode}")
            return False
        return True
    
    def run_java_import(db_filename, cpg_dir):
        """Neo4j"""
        print(f'[{repo_name}] neo4j database generating...')
        
        # postpatch
        if db_filename.endswith("postpatch"):
            bolt_port = "17687"
            http_port = "17474"
        else:
            bolt_port = "7687"
            http_port = "7474"
        
        # cpg_dircsv
        result = subprocess.run(
            ["bash", 
             os.path.join(PHPJOERN_HOME, "neo4j-admin-import_vari.sh"),
             db_filename, bolt_port, http_port, neo4j_home],
            cwd=cpg_dir
        )
        
        if result.returncode != 0:
            print(f"[{repo_name}] admin import failed with return code: {result.returncode}")
            return False
        
        subprocess.run(
            ["chown", "-R", ":", db_filename], 
            cwd=neo4j_home
        )
        return True
    
    def cleanup_cpg_dir():
        """CPG"""
        if os.path.exists(cpg_project_dir):
            print(f"[{repo_name}] cleaning up {cpg_project_dir} due to failure")
            shutil.rmtree(cpg_project_dir, ignore_errors=True)
    
    try:
        # Step 1: php2ast
        if not run_php2ast(repo_dir, nodes_path, rels_path):
            cleanup_cpg_dir()
            return False, "php2ast_pre"
        
        # Step 2: phpast2cpg
        if not run_phpast2cpg(nodes_path, rels_path, cpg_project_dir):
            cleanup_cpg_dir()
            return False, "phpast2cpg_pre"
        
        # Step 3: Neo4j import
        if not run_java_import(repo_name, cpg_project_dir):
            cleanup_cpg_dir()
            return False, "batch_import_pre"
        
        print(f"[{repo_name}] ✅ ")
        return True, None
        
    except Exception as e:
        print(f"[{repo_name}] Error: {traceback.format_exc()}")
        cleanup_cpg_dir()
        return False, str(e)


def filter_patch_sink_paths(all_paths, potential_funcname_list: List[str]):
    filtered_paths = []
    for path in all_paths:
        for node in path:
            if "marker" in node:
                if node["marker"] == "SOURCE":
                    filtered_paths.append(path)
                    break
            elif "callee_name" in node:
                if node["callee_name"] in potential_funcname_list:
                    filtered_paths.append(path)
                    break
                elif node["call_site_code"] in potential_funcname_list:
                    filtered_paths.append(path)
                    break
            elif "caller_name" in node:
                if node["caller_name"] in potential_funcname_list:
                    filtered_paths.append(path)
                    break
                elif node["call_site_code"] in potential_funcname_list:
                    filtered_paths.append(path)
                    break
            
    all_paths.clear()
    all_paths.extend(filtered_paths)


def extract_adjacent_relations(call_path):
    relations = []
    for i in range(len(call_path)-1):
        a = call_path[i]
        b = call_path[i+1]
        # If both param_pos == -1 -> no call relation (skip)
        if a.get('param_pos', -1) == -1 and b.get('param_pos', -1) == -1:
            continue
        # There's a potential relation. Determine direction based on keys in the next item.
        if 'callee_name' in b:
            # a (caller_name) -> b (callee_name)
            left = a.get('caller_name') or a.get('callee_name') or a.get('call_site_code') or f"func_{a.get('funcid','?')}"
            right = b.get('callee_name') or f"func_{b.get('funcid','?')}"
            relations.append((left, right))
        elif 'caller_name' in b:
            # relation reversed: b (caller_name) -> a (caller_name or callee)
            left = b.get('call_site_code') or f"func_{b.get('funcid','?')}"
            # prefer caller_name of a, fall back to callee_name or funcid
            right = a.get('call_site_code') or f"func_{a.get('funcid','?')}"
            relations.append((left, right))
            if 'level' in a:
                left = b.get('caller_name') or f"func_{b.get('funcid','?')}"
                right = b.get('call_site_code') or f"func_{b.get('funcid','?')}"
                relations.append((left, right))
            
        else:
            # If neither key exists, try to infer using available names
            left = a.get('caller_name') or a.get('callee_name') or f"func_{a.get('funcid','?')}"
            right = b.get('caller_name') or b.get('callee_name') or f"func_{b.get('funcid','?')}"
            relations.append((left, right))

    relations = list(set(relations))
    for (l, r) in relations:
        if l.endswith(".php") or r.endswith(".php"):
            relations.remove((l, r))
    return relations


def ss_in_inter(call_path):
    init_funcid = -1
    if call_path:
        init_funcid = call_path[0]['funcid']
    for node in call_path:
        if node['funcid'] != init_funcid:
            return True
    return False


def clear_port_pool():
    """"""
    while not PORT_POOL.empty():
        try:
            PORT_POOL.get_nowait()
        except queue.Empty:
            break

def initialize_port_pool(num_workers):
    """"""
    for i in range(num_workers):
        bolt_port = BASE_BOLT_PORT + i
        http_port = BASE_HTTP_PORT + i
        PORT_POOL.put((bolt_port, http_port))

def get_port_pair():
    """"""
    return PORT_POOL.get()


def return_port_pair(bolt_port, http_port):
    """"""
    PORT_POOL.put((bolt_port, http_port))


def copy_database_with_port(original_db_name, bolt_port, http_port, split_num=1):
    """
    
    
    Args:
        original_db_name: 
        bolt_port: Bolt
        http_port: HTTP
    
    Returns:
        
    """
    original_path = os.path.join(DATABASE_PATH, original_db_name)
    new_db_name = f"{original_db_name}_{bolt_port}"
    new_path = os.path.join(DATABASE_PATH, new_db_name)
    
    # 
    if os.path.exists(new_path):
        print(f"[*] Database copy {new_db_name} already exists, skipping copy...")
        return new_db_name
    
    print(f"[*] Copying database from {original_db_name} to {new_db_name}...")
    shutil.copytree(original_path, new_path)
    
    # 
    conf_file = os.path.join(new_path, "conf/neo4j.conf")
    change_jvmprocessor_port(conf_file, count=NUM_WORKERS//split_num)
    change_bolt_port(conf_file, bolt_port)
    change_https_port(conf_file, http_port)
    
    print(f"[+] Database {new_db_name} created with bolt_port={bolt_port}, http_port={http_port}")
    return new_db_name


def create_database_copies(original_db_name, num_copies):
    """
    
    
    Args:
        original_db_name: 
        num_copies: 
    
    Returns:
        
    """
    db_copies = []
    print(f"\n[*] Creating {num_copies} database copies for {original_db_name}...")
    
    for i in range(num_copies):
        bolt_port = BASE_BOLT_PORT + i
        http_port = BASE_HTTP_PORT + i
        new_db_name = copy_database_with_port(original_db_name, bolt_port, http_port, num_copies)
        db_copies.append(new_db_name)
    
    print(f"[+] Successfully created {len(db_copies)} database copies")
    return db_copies


def start_database_with_port(db_name, database_path=None):
    """"""
    if database_path is None:
        database_path = DATABASE_PATH
    db_path = os.path.join(database_path, db_name)
    
    if not os.path.exists(db_path):
        print(f"[!] Database path {db_path} does not exist.")
        return False
    
    # 
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
    
    # 
    print(f"[*] Starting database {db_name}...cmd: {db_path}/bin/neo4j")
    subprocess.run(
        [f"{db_path}/bin/neo4j", "start"],
        capture_output=True,
        text=True,
        check=False
    )
    
    # 
    time.sleep(10)
    
    # 
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


def stop_database_with_port(db_name, database_path=None):
    """"""
    if database_path is None:
        database_path = DATABASE_PATH
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


def check_database_with_port(db_name, database_path=None):
    """"""
    if database_path is None:
        database_path = DATABASE_PATH
    db_path = os.path.join(database_path, db_name)
    
    if not os.path.exists(db_path):
        return False, None
    
    result = subprocess.run(
        [f"{db_path}/bin/neo4j", "status"],
        capture_output=True,
        text=True,
        check=False
    )
    out = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    low = out.lower()
    running = (result.returncode == 0) and ("is running at pid" in low or "is running" in low)
    
    pid = None
    m = re.search(r"\bpid\s+(\d+)\b", low)
    if m:
        pid = int(m.group(1))

    if running:
        print(f"[+] {db_name} is running (pid={pid})")
    else:
        print(f"[!] {db_name} is not running")

    return running, pid


def change_https_port(filepath, https_port):
    """HTTP"""
    if not os.path.exists(filepath):
        return
    
    with open(filepath, 'r') as file:
        lines = file.readlines()
    
    with open(filepath, 'w') as file:
        for line in lines:
            if line.startswith("dbms.connector.http.listen_address=:"):
                file.write(f"dbms.connector.http.listen_address=:{https_port}\n")
            else:
                file.write(line)


def change_bolt_port(filepath, bolt_port):
    """Bolt"""
    if not os.path.exists(filepath):
        return
    
    with open(filepath, 'r') as file:
        lines = file.readlines()
    
    with open(filepath, 'w') as file:
        for line in lines:
            if line.startswith("dbms.connector.bolt.listen_address=:"):
                file.write(f"dbms.connector.bolt.listen_address=:{bolt_port}\n")
            else:
                file.write(line)

def change_jvmprocessor_port(filepath, count=96, workers=96):
    """Bolt"""
    if not os.path.exists(filepath):
        return
    
    with open(filepath, 'r') as file:
        lines = file.readlines()
    
    with open(filepath, 'w') as file:
        for line in lines:
            if line.startswith("dbms.jvm.additional=-XX:+UseG1GC"):
                file.write(f"dbms.jvm.additional=-XX:+UseG1GC\ndbms.jvm.additional=-XX:ActiveProcessorCount={count}\n")
            elif line.startswith("dbms.threads.worker_count="):
                file.write(f"dbms.threads.worker_count={workers}\n")
            elif line.startswith("#dbms.threads.worker_count="):
                file.write(f"dbms.threads.worker_count={workers}\n")
            else:
                file.write(line)


def cleanup_database_copies(original_db_name, num_copies):
    """"""
    timeout=30
    poll_interval=0.5
    print(f"\n[*] Cleaning up database copies...")
    for i in range(num_copies):
        bolt_port = BASE_BOLT_PORT + i
        db_name = f"{original_db_name}_{bolt_port}"
        stop_database_with_port(db_name)

    for i in range(num_copies):
        deadline = time.time() + timeout
        bolt_port = BASE_BOLT_PORT + i
        db_name = f"{original_db_name}_{bolt_port}"
        last_pid = None
        
        while True:
            running, pid = check_database_with_port(db_name)
            last_pid = pid
            if not running:
                break

            if time.time() > deadline:
                if last_pid:
                    print(f"[!] Timeout. Force killing {db_name} pid={last_pid} ...")
                    try:
                        os.kill(last_pid, signal.SIGKILL)  #  kill -9
                    except ProcessLookupError:
                        print(f"[!] pid {last_pid} not found (already exited)")
                    except PermissionError:
                        print(f"[!] Permission denied killing pid {last_pid} (need sudo?)")
                    except Exception as e:
                        print(f"[!] Failed to kill pid {last_pid}: {e}")

                    time.sleep(0.5)
                else:
                    print(f"[!] Timeout but no pid parsed for {db_name}, continue to delete anyway.")
                break

            time.sleep(poll_interval)

        time.sleep(0.5)
        db_path = os.path.join(DATABASE_PATH, db_name)
        if os.path.exists(db_path):
            try:
                shutil.rmtree(db_path)
                print(f"[+] Removed {db_name}")
            except Exception as e:
                print(f"[!] Failed to remove {db_name}: {e}")


def process_single_sink_with_db(potential_sink, vuln_type, already_processed_sink_nodes, 
                                 timeout_node_list, target, original_db_name, 
                                 processed_nodes_lock, timeout_nodes_lock, file_write_lock,
                                 source_lock, not_source_lock, intra_record_lock, inter_record_lock,
                                 already_processed_sink_nodes_file, timeout_nodes_file,
                                 default_dir, extend_vuln_model,
                                 all_potential_source,
                                 all_not_source_funcname_list,
                                 intra_source_sink_record,
                                 inter_source_sink_record,
                                 target_detection_source_finder_path,
                                 all_not_source_funcname_list_path,
                                 api_key, model):
    """
    sink
    """
    # 
    # bolt_port, http_port = get_port_pair()
    bolt_port, http_port = BASE_BOLT_PORT, BASE_HTTP_PORT
    db_name = f"{original_db_name}_{bolt_port}"
    print(f"[Worker-{bolt_port}] use database {db_name} for SOURCE FINDER.")
    
    try:
        # 
        with processed_nodes_lock:
            if potential_sink.node_id in already_processed_sink_nodes:
                print(f"[+] Skip already processed node {potential_sink.node_id}...")
                return
        
        with timeout_nodes_lock:
            if potential_sink.node_id in timeout_node_list:
                print(f"[+] Skip timeout node {potential_sink.node_id}...")
                return
        
        # 
        slice_dir = os.path.join(default_dir, target, VULN_TYPE_DICT[vuln_type].replace(" ", "_"))
        slice_dir_sp = os.path.join(slice_dir, f"sink_{potential_sink.node_id}")
        inter_to_intra_dir = os.path.join(default_dir, target, "inter_to_intra", 
                                          VULN_TYPE_DICT[vuln_type].replace(" ", "_"))
        
        if os.path.exists(slice_dir_sp):
            final_exist = True
            for src_sink_slice in os.listdir(slice_dir_sp):
                idx = src_sink_slice.split("src_sink_path_")[-1].split(".php")[0]
                if not os.path.exists(f"{inter_to_intra_dir}/{idx}.php"):
                    final_exist = False
                    break
            if final_exist:
                print(f"[+] Slice for sink {potential_sink.node_id} already exists. skip...")
                return
        
        # 
        if not start_database_with_port(db_name):
            print(f"[!] Failed to start database {db_name}")
            return
        
        # analyzer
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
        # analyzer_target = Neo4jEngine.from_dict(config_dict["all_prepatch"])
        while True:
            try:
                analyzer_target = Neo4jEngine.from_dict(config_dict["all_prepatch"])
                break
            except Exception as e:
                print(f" {bolt_port} ... : {e}")
                time.sleep(3)
        
        # 
        context_slicer = ContextSlicer(
            anchor_node=potential_sink,
            analyzer=analyzer_target,
            vuln_type=VULN_TYPE_DICT[vuln_type],
            max_caller_depth=2,
            max_callee_depth=1
        )
        
        TIMEOUT = 300
        with ThreadPoolExecutor() as executor:
            future = executor.submit(context_slicer.detection_run, repo=target)
            try:
                sink_funcname = future.result(timeout=TIMEOUT)
            except TimeoutError:
                print(f"[timeout] ,  {potential_sink.node_id}")
                with timeout_nodes_lock:
                    timeout_node_list.append(potential_sink.node_id)
                    with file_write_lock:
                        with open(timeout_nodes_file, "w", encoding="utf-8") as f:
                            json.dump(timeout_node_list, f, ensure_ascii=False, indent=4)
                return
            
        # 
        potential_source_funcname_list = context_slicer.potential_source_funcname
        find_source_by_llm = False
        potential_source_funcname_list_by_llm = []



        #   source
        if context_slicer.sources.__len__() == 0:
            with processed_nodes_lock:
                already_processed_sink_nodes.add(potential_sink.node_id)
                with file_write_lock:
                    with open(already_processed_sink_nodes_file, "w", encoding="utf-8") as f:
                        json.dump(list(already_processed_sink_nodes), f, ensure_ascii=False, indent=4)
            print("[-] No built-in source found in backward slicing.")
            find_source_builtin = False
        else:
            find_source_builtin = True
            print("[+] Found built-in source(s) in backward slicing.")



        if potential_source_funcname_list:
            # 
            print(f"[+] First round found {potential_source_funcname_list.__len__()} potential funcalls.")
            
            with not_source_lock:
                funcalls_to_check = [func for func in potential_source_funcname_list 
                                   if func.split("(")[0].strip() not in all_not_source_funcname_list]

            with source_lock:
                potential_source_funcname_list_by_llm = [func.split("(")[0].strip() for func in funcalls_to_check 
                                                        if func.split("(")[0].strip() in all_potential_source]
                if potential_source_funcname_list_by_llm:
                    find_source_by_llm = True

                funcalls_to_check = [func for func in funcalls_to_check 
                                   if func.split("(")[0].strip() not in all_potential_source]

            if not funcalls_to_check:
                # LLM  source
                with processed_nodes_lock:
                    already_processed_sink_nodes.add(potential_sink.node_id)
                    with file_write_lock:
                        with open(already_processed_sink_nodes_file, "w", encoding="utf-8") as f:
                            json.dump(list(already_processed_sink_nodes), f, ensure_ascii=False, indent=4)
                
                if find_source_by_llm:
                    print("[+]  source source LLM")
                else:
                    print("[-]  sourceLLM")
                    if find_source_builtin:
                        print("[+] But built-in source exists, continue slicing...")
                    else:
                        print("[-] No source found at all (builtin and llm), skip slicing...")
                        return
            else:
                # LLM 
                print("[*] Query LLM for potential sources...")
                potential_source_funcname_list_by_llm = llm_find_potential_source(funcalls_to_check, api_key=api_key, model=model)

                # source
                with not_source_lock:
                    for func in funcalls_to_check:
                        if func.split("(")[0].strip() not in potential_source_funcname_list_by_llm:
                            all_not_source_funcname_list.add(func.split("(")[0].strip())

                with processed_nodes_lock:
                    already_processed_sink_nodes.add(potential_sink.node_id)
                    with file_write_lock:
                        with open(already_processed_sink_nodes_file, "w", encoding="utf-8") as f:
                            json.dump(list(already_processed_sink_nodes), f, ensure_ascii=False, indent=4)

                if not potential_source_funcname_list_by_llm:
                    print("[-] Cannot find any source function call with LLM !!!")
                    if find_source_builtin:
                        print("[+] But built-in source exists, continue slicing...")
                    else:
                        print("[-] No source found at all (builtin and llm), skip slicing...")
                        return
                else:
                    print(f"[+] LLM find {potential_source_funcname_list_by_llm.__len__()} potential sources: {potential_source_funcname_list_by_llm}")
                    with source_lock:
                        all_potential_source.update(potential_source_funcname_list_by_llm)
                    find_source_by_llm = True

            # 
            with source_lock:
                with file_write_lock:
                    with open(target_detection_source_finder_path, "w", encoding="utf-8") as f:
                        json.dump(list(all_potential_source), f, ensure_ascii=False, indent=4)

            with not_source_lock:
                with file_write_lock:
                    with open(all_not_source_funcname_list_path, "w", encoding="utf-8") as f:
                        json.dump(list(all_not_source_funcname_list), f, ensure_ascii=False, indent=4)


        else:
            if not find_source_builtin:
                print("[-] No potential source function calls found in backward slicing, skip slicing...")
                return

        print("\n[+] Found potential sources, start slicing... \n")
        source_sink_path = filter_patch_sink_paths(context_slicer.backward_call_paths, potential_source_funcname_list_by_llm)

        slicer = InterproceduralForwardSlicer(analyzer_target, direction="sp", star_range=STAR_RANGE, repo_prefix="detection_projects_0120_papers")
        if os.path.exists(slice_dir_sp) and os.listdir(slice_dir_sp).__len__() > 0:
            print(f"[+] Slice for sink {potential_sink.node_id} already exists. skip slicing... GOTO LLM fixing")
        else:
            with file_write_lock:
                os.makedirs(slice_dir, exist_ok=True)
                os.makedirs(slice_dir_sp, exist_ok=True)
            merge_call_paths = context_slicer.backward_call_paths

            for idx, call_path in enumerate(merge_call_paths):
                call_relateions = []
                new_call_path = slicer.convert_backward_to_forward(call_path)
                # 
                if ss_in_inter(call_path):
                    output_file = f"{slice_dir_sp}/src_sink_path_{potential_sink.node_id}_{idx}_inter.php"

                    if os.path.exists(output_file):
                        print(f"[+] {output_file} already exists. skip slicing ...")
                        continue

                    call_relateions = extract_adjacent_relations(call_path)

                    slice_result = slicer.forward_slice_source_sink(new_call_path)
                    print(f"[+] Source and sink are in different functions for sink node {potential_sink.node_id}.")
                
                else: 
                    # 
                    sink_source_belong_file = new_call_path[0].get("location", {}).get("file", None)
                    sink_source_belong_file = slicer.transform_path(sink_source_belong_file)
                    output_file = f"{slice_dir_sp}/src_sink_path_{potential_sink.node_id}_{idx}_intra.php"
                    if sink_source_belong_file:
                        with file_write_lock:
                            with open(f"{output_file}", "w", encoding="utf-8") as f:
                                with open(sink_source_belong_file, "r", encoding="utf-8") as sf:
                                    f.write(sf.read())
                        print(f"[+] Source and sink are in the same function for sink node {potential_sink.node_id}, saved the whole file {sink_source_belong_file} to {output_file}.")
                        continue
                    else:
                        print(f"[-] Cannot find the source/sink belonging file for sink node {potential_sink.node_id}, skip saving intra slice.")
                        continue
                    # slice_result = slicer.forward_slice_intra([new_call_path[-1]])
                    # print(f"[+] Source and sink are in the same function for sink node {potential_sink.node_id}.")

                if os.path.exists(output_file):
                    print(f"[+] {output_file} already exists. skip slicing ...")
                    continue
                with file_write_lock:
                    code_output = slicer.export_slice_code(slice_result, output_file, call_relateions)
                print(f"[+] Export slice code to {output_file}")

        # 
        # inter_to_intra_dir = os.path.join(slice_dir, "inter_to_intra")
        # 
        print("[+] Start LLM fixing and merging sliced code...")

        with file_write_lock:
            os.makedirs(inter_to_intra_dir, exist_ok=True)
        
        #  prompt +
        for src_sink_slice in os.listdir(slice_dir_sp):
            with open(os.path.join(slice_dir_sp, src_sink_slice), 'r') as f:
                ss_code = f.read()
            idx = src_sink_slice.split("src_sink_path_")[-1].split(".php")[0]
            inter_flag = "_inter" in src_sink_slice
            
            #  LLM 
            if os.path.exists(f"{inter_to_intra_dir}/{idx}.php"):
                print(f"[+] {inter_to_intra_dir}/{idx}.php already exists. skip LLM processing ...")
                continue

            if inter_flag: 
                # LLM  + 
                if ss_code.strip().split("\n").__len__() > 300 or ss_code.strip().split("\n").__len__() < 3:
                    with open(f"{inter_to_intra_dir}/{idx}.php", "w") as f:
                        f.write("<?php\n phpinfo();\n")
                else:
                    source_sink_slice_fix_and_merge(
                        ", ".join(potential_source_funcname_list_by_llm), 
                        ", ".join([sink_funcname]), 
                        ss_code, inter_to_intra_dir, idx, model=model, api_key=api_key
                    )
            else:
                # 
                os.system(f"cp {os.path.join(slice_dir_sp, src_sink_slice)} {inter_to_intra_dir}/{idx}.php")
        
        # 
        with processed_nodes_lock:
            already_processed_sink_nodes.add(potential_sink.node_id)
            with file_write_lock:
                with open(already_processed_sink_nodes_file, "w", encoding="utf-8") as f:
                    json.dump(list(already_processed_sink_nodes), f, ensure_ascii=False, indent=4)
        
    except Exception as e:
        print(f"[!] Error processing sink {potential_sink.node_id}: {e}")
        traceback.print_exc()
    finally:
        pass
        # 
        # stop_database_with_port(db_name)
        # 
        # return_port_pair(bolt_port, http_port)


def run_capture_potential_src_sink_multithread(target, extend_vuln_model, num_workers, num_neo4j_instances=4) -> bool:
    """
    sink
    """

    print("extend_vuln_model:")
    print(extend_vuln_model)

    original_db_name = f"{target}"

    clear_port_pool()
    
    # 
    initialize_port_pool(num_neo4j_instances)
    
    # 
    print(f"\n[*]  {num_neo4j_instances} Neo4j...")
    create_database_copies(original_db_name, num_neo4j_instances)
    
    try:
        # sink
        bolt_port, http_port = get_port_pair()
        first_db_name = f"{original_db_name}_{bolt_port}"
        
        if not start_database_with_port(first_db_name):
            print(f"[-] Failed to start first database for sink loading")
            return set(), False
        
        # input("...")
        
        # potential sinks
        if os.path.exists(f"./potential_sinks_detection_{STAR_RANGE}/{target}.pkl"):
            print("Loading potential sinks from cache...")
            with open(f"./potential_sinks_detection_{STAR_RANGE}/{target}.pkl", "rb") as f:
                potential_sink_dict = pickle.load(f)
        else:
            # cc_run
            from core.target_sink_finder import cc_run_parallel
            
            start_time = time.time()
            potential_sink_dict = cc_run_parallel(
                original_db_name=original_db_name,
                target=target,
                extend_vuln_model=extend_vuln_model,
                sink_file=None,
                num_workers=num_workers,
                num_neo4j_instances=num_neo4j_instances,
                DATABASE_PATH=DATABASE_PATH,
                base_bolt_port=BASE_BOLT_PORT,
                base_http_port=BASE_HTTP_PORT
            )
            end_time = time.time()
            print(f"[*] Target sink finding time: {end_time - start_time} seconds")
            
            zero_anchors = True
            for vt, anchor_nodes in potential_sink_dict.items():
                if anchor_nodes.__len__() != 0:
                    zero_anchors = False
                    break
            
            if zero_anchors:
                print("[-] No potential sinks found. Exiting...")
                return set(), False
            
            with open(f"./potential_sinks_detection_{STAR_RANGE}/{target}.pkl", "wb") as f:
                pickle.dump(potential_sink_dict, f)
            print("Saved potential sinks to cache.")
        
        
        # input("...")
        return_port_pair(bolt_port, http_port)
        # 
        default_dir = f"./detection_inter_slice_result_{STAR_RANGE}"
        intra_source_sink_dir = "./detection_intra_source_sink_record"
        detection_source_finder_dir = "./detection_source_finder"
        os.makedirs(detection_source_finder_dir, exist_ok=True)
        os.makedirs(intra_source_sink_dir, exist_ok=True)
        os.makedirs(default_dir, exist_ok=True)


        target_detection_source_finder_path = os.path.join(detection_source_finder_dir, f"{target}_all_source_funcname_list.json")
        all_not_source_funcname_list_path = os.path.join(detection_source_finder_dir, f"{target}_all_not_source_funcname_list.json")
        project_potential_intra_ss_record_path = os.path.join(intra_source_sink_dir, f"{target}_intra_source_sink_record.json")
        os.makedirs(intra_source_sink_dir, exist_ok=True)
        project_potential_inter_ss_record_path = os.path.join(intra_source_sink_dir, f"{target}_inter_source_sink_record.json")

        # 
        if os.path.exists(target_detection_source_finder_path):
            with open(target_detection_source_finder_path, "r", encoding="utf-8") as f:
                all_potential_source = set(json.load(f))
        else:
            all_potential_source = set()
        
        if os.path.exists(all_not_source_funcname_list_path):
            with open(all_not_source_funcname_list_path, "r", encoding="utf-8") as f:
                all_not_source_funcname_list = set(json.load(f))
        else:
            all_not_source_funcname_list = set()

        if os.path.exists(project_potential_intra_ss_record_path):
            with open(project_potential_intra_ss_record_path, "r", encoding="utf-8") as f:
                intra_source_sink_record = json.load(f)
        else:
            intra_source_sink_record = dict()

        if os.path.exists(project_potential_inter_ss_record_path):
            with open(project_potential_inter_ss_record_path, "r", encoding="utf-8") as f:
                inter_source_sink_record = json.load(f)
        else:
            inter_source_sink_record = dict()
        
        # 
        processed_nodes_lock = threading.Lock()
        timeout_nodes_lock = threading.Lock()
        file_write_lock = threading.Lock()
        source_lock = threading.Lock()
        not_source_lock = threading.Lock()
        intra_record_lock = threading.Lock()
        inter_record_lock = threading.Lock()
        
        all_tasks = []  # : (sink, vuln_type, metadata)
        vuln_type_metadata = {}  # 

        for vuln_type in VULN_TYPE_DICT.keys():
            # if vuln_type in {10}:
            #     continue
            print(f" {VULN_TYPE_DICT[vuln_type]} ...")
            
            # 
            already_processed_sink_nodes_file = f"./detection_record_{STAR_RANGE}/{target}/{VULN_TYPE_DICT[vuln_type]}_already_processed_nodes.json"
            os.makedirs(os.path.join(f"./detection_record_{STAR_RANGE}", target), exist_ok=True)
            timeout_nodes_file = f"./detection_record_{STAR_RANGE}/{target}/{VULN_TYPE_DICT[vuln_type]}_timeout_nodes.txt"
            
            # 
            already_processed_sink_nodes = set()
            if os.path.exists(already_processed_sink_nodes_file):
                with open(already_processed_sink_nodes_file, "r", encoding="utf-8") as f:
                    already_processed_sink_nodes = set(json.load(f))
            
            if os.path.exists(timeout_nodes_file):
                with open(timeout_nodes_file, "r", encoding="utf-8") as f:
                    timeout_node_list = json.load(f)
            else:
                timeout_node_list = []
            
            # 
            vuln_type_metadata[vuln_type] = {
                'already_processed_file': already_processed_sink_nodes_file,
                'timeout_file': timeout_nodes_file,
                'already_processed_nodes': already_processed_sink_nodes,
                'timeout_nodes': timeout_node_list
            }
            
            # sink
            potential_sink_list = potential_sink_dict[vuln_type]
            
            if len(potential_sink_list) == 0:
                print(f"  [-] {VULN_TYPE_DICT[vuln_type]}: 0 ")
                continue
            
            unprocessed_sinks = [
                sink for sink in potential_sink_list
                if sink.node_id not in already_processed_sink_nodes 
                and sink.node_id not in timeout_node_list
            ]
            
            print(f"  [+] {VULN_TYPE_DICT[vuln_type]}: {len(unprocessed_sinks)}  ( {len(potential_sink_list)} )")
            
            # 
            for sink in unprocessed_sinks:
                all_tasks.append((sink, vuln_type))
        
        if not all_tasks:
            print("[-] sink...")
            return all_potential_source, False
        
        print(f"\n: {len(all_tasks)} sink")
        print("============================")
        print("sink...")
        print("============================\n")
        
        # 
        if all_tasks.__len__() < num_workers:
            num_workers = all_tasks.__len__()
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures_to_task = {}
            
            for idx, (sink, vuln_type) in enumerate(all_tasks):
                metadata = vuln_type_metadata[vuln_type]
                model="gpt-5-2025-08-07"
                api_key = API_KEY[idx % len(API_KEY)]
                future = executor.submit(
                    process_single_sink_with_db, 
                    sink, vuln_type, 
                    metadata['already_processed_nodes'], 
                    metadata['timeout_nodes'],
                    target, original_db_name, 
                    processed_nodes_lock, timeout_nodes_lock, file_write_lock,
                    source_lock, not_source_lock, intra_record_lock, inter_record_lock,
                    metadata['already_processed_file'], 
                    metadata['timeout_file'],
                    default_dir, extend_vuln_model,
                    all_potential_source,
                    all_not_source_funcname_list,
                    intra_source_sink_record,
                    inter_source_sink_record,
                    target_detection_source_finder_path,
                    all_not_source_funcname_list_path,
                    api_key, model
                )
                futures_to_task[future] = (sink, vuln_type)
            
            # tqdm
            completed_count = 0
            vuln_type_stats = {vt: {'completed': 0, 'total': 0} for vt in VULN_TYPE_DICT.keys()}
            
            # 
            for _, vuln_type in all_tasks:
                vuln_type_stats[vuln_type]['total'] += 1
            
            for future in tqdm(as_completed(futures_to_task), total=len(all_tasks), desc=""):
                sink_node, vuln_type = futures_to_task[future]
                try:
                    future.result()
                    completed_count += 1
                    vuln_type_stats[vuln_type]['completed'] += 1
                except Exception as e:
                    print(f"\n[Error]  {sink_node.node_id} ({VULN_TYPE_DICT[vuln_type]}) : {e}")

        # 
        print("\n============================")
        print(":")
        print("============================")
        for vuln_type, stats in vuln_type_stats.items():
            if stats['total'] > 0:
                print(f"  {VULN_TYPE_DICT[vuln_type]}: {stats['completed']}/{stats['total']} ")
        print(f"\n: {completed_count}/{len(all_tasks)} \n")
        
        return all_potential_source, True
        
    finally:
        # 
        cleanup_database_copies(original_db_name, num_neo4j_instances)
    


def main():
    GENE_CPG_FLAG = False
    EXTRACT_SINK_FLAG = False
    model = "gpt-5"
    target_repo = TARGET_REPO
    
    repo_sink_dict = json.load(open(f"./potential_sinks_detection/repo_sink_dict_gpt-5_{STAR_RANGE}.json", "r")) \
        if os.path.exists(f"./potential_sinks_detection/repo_sink_dict_gpt-5_{STAR_RANGE}.json") else dict()
    
    all_potential_source_dir = f"./detection_source_finder"
    detection_projects_neo4j = DATABASE_PATH
    buchuli_process_repo = ["kleeja", "phppgadmin", "openduka"]

    for target, potential_sinks in repo_sink_dict.items():
        if not os.path.exists(f"{detection_projects_neo4j}{target}_prepatch"):
            print(f"[-] {target} neo4j database not exist. skip ...")
            print(f"{detection_projects_neo4j}{target}_prepatch")
            continue

        if target_repo and target != target_repo:
            continue
        
        if target in buchuli_process_repo:
            print(f"[-] {target} . skip ...")
            continue

        print(f"\n\nProcessing {target}...\n")
        
        
        potential_sinks = repo_sink_dict.get(target, None)
        if potential_sinks is None: # or potential_sinks.__len__() == 0:
            print(f"[-] Cannot find potential sinks for {target}. skip ...")
            continue
        
        _map_key_1 = target
        
        detection_record_dir = f"./detection_record_{STAR_RANGE}"
        os.makedirs(detection_record_dir, exist_ok=True)
        all_detection_project_path = os.path.join(detection_record_dir, "all_detection_project.json")
        
        if os.path.exists(all_detection_project_path):
            with open(all_detection_project_path, "r", encoding="utf-8") as f:
                all_detection_project = json.load(f)
        else:
            all_detection_project = []
        
        # if target in all_detection_project:
        #     print(f"[+] {target} already processed in all_detection_project. skip ...")
        #     continue
        
        try:
            detection_inter_slice_result_neo4j_dir = f"./detection_inter_slice_result_neo4j_{STAR_RANGE}"
            os.makedirs(detection_inter_slice_result_neo4j_dir, exist_ok=True)
            all_potential_source = set()
            if not os.path.exists(f"{detection_inter_slice_result_neo4j_dir}/{_map_key_1}_prepatch"):
                all_potential_source, state = run_capture_potential_src_sink_multithread(
                    f"{_map_key_1}_prepatch", 
                    {9: potential_sinks},
                    NUM_WORKERS,
                    NUM_NEO4J_INSTANCES
                )
                
                if not state:
                    print("sink")
                    all_detection_project.append(target)
                    with open(all_detection_project_path, "w", encoding="utf-8") as f:
                        json.dump(all_detection_project, f, ensure_ascii=False, indent=4)
                    continue
                
                print(" source sink neo4j cpg")
                all_detection_project.append(target)
                with open(all_detection_project_path, "w", encoding="utf-8") as f:
                    json.dump(all_detection_project, f, ensure_ascii=False, indent=4)

            if all_potential_source.__len__() == 0:
                target_source_data = json.load(open(f"./detection_source_finder/{_map_key_1}_prepatch_all_source_funcname_list.json", "r", encoding="utf-8"))
                all_potential_source = set(target_source_data)
            if run_sig_source_sink(f"{_map_key_1}_prepatch", all_potential_source, {9: potential_sinks}, NUM_WORKERS):
                print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} The target {target} is vulnerable")
                #  all_detection_project
                all_detection_project.append(target)
                with open(all_detection_project_path, "w", encoding="utf-8") as f:
                    json.dump(all_detection_project, f, ensure_ascii=False, indent=4)
            else:
                print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {target} ")
            
        except Exception as e:
            print(traceback.format_exc())



def run_sig_source_sink(target, potential_source, extend_vuln_model, num_workers) -> bool:
    print("\nsink\n")
    task = "detection"

    detection_intra_source_sink_record_dir = f"./{task}_intra_source_sink_record_{STAR_RANGE}/"
    detection_inter_slice_result_neo4j_dir = f"./{task}_inter_slice_result_neo4j_{STAR_RANGE}"
    detection_inter_slice_result_signature_dir = f"./{task}_intra_slice_result_signature_{STAR_RANGE}"
    os.makedirs(detection_inter_slice_result_signature_dir, exist_ok=True)
    
    
    target_detection_inter_slice_result_signature_path = os.path.join(detection_inter_slice_result_signature_dir, f"{target}_final_sink_context.json")
    
    target_detection_inter_slice_result_dataflow_str_path = os.path.join(detection_inter_slice_result_signature_dir, f"{target}_final_dataflow_str_list.json")

    if os.path.exists(target_detection_inter_slice_result_signature_path) and \
       os.path.exists(target_detection_inter_slice_result_dataflow_str_path):
        print(f"[+] Sink context and dataflow for {target} already exists. skip ... \n")
        return True

    final_sink_context = {'inter': {}}
    final_dataflow_str_list = {'inter': []}

    #  Neo4j 
    target_neo4j_path = os.path.join(detection_inter_slice_result_neo4j_dir, target)
    if not os.path.exists(target_neo4j_path):
        print(f"[-] Neo4j database not found for {target} at {target_neo4j_path}")
        return False
    
    print(f"[+] Starting Neo4j database for {target_neo4j_path}...")
    states = start_database_with_port(target, detection_inter_slice_result_neo4j_dir)

    config_dict = {
        "all_prepatch": {
            "NEO4J_HOST": "localhost",
            "NEO4J_PORT": "7687",
            "NEO4J_USERNAME": "neo4j",
            "NEO4J_PASSWORD": "password",
            "NEO4J_DATABASE": "neo4j",
            "NEO4J_PROTOCOL": "bolt"
        }
    }

    # 
    print("[+] Connecting to Neo4j database...")
    max_retries = 10
    retry_count = 0
    analyzer = None
    
    while retry_count < max_retries:
        try:
            analyzer = Neo4jEngine.from_dict(config_dict["all_prepatch"])
            print("[+] Successfully connected to Neo4j database!")
            break
        except Exception as e:
            retry_count += 1
            print(f"[-] Connection attempt {retry_count}/{max_retries} failed: {e}")
            if retry_count < max_retries:
                print("[+] Retrying in 3 seconds...")
                time.sleep(3)
            else:
                print("[-] Failed to connect to Neo4j database after maximum retries")
                stop_database_with_port(target, detection_inter_slice_result_neo4j_dir)
                return False

    try:
        # sink_finder = TargetSinkFinder(analysis_framework=analyzer, git_repository=target)
        # sink_finder.cc_run(extend_vuln_model)
        # potential_sink_dict = sink_finder.potential_sinks
        from core.target_sink_finder import cc_run_parallel
        potential_sink_dict = cc_run_parallel(
            original_db_name=target,
            target=target,
            extend_vuln_model=extend_vuln_model,
            sink_file=None,
            num_workers=num_workers,
            num_neo4j_instances=1,
            DATABASE_PATH=detection_inter_slice_result_neo4j_dir,
            base_bolt_port=7687,
            base_http_port=7474
        )
        TIMEOUT_SECONDS = 360  # 6
        MULTI_THREADING_ENABLED = True
        for vuln_type in VULN_TYPE_DICT.keys():
            # if vuln_type not in {9}:
            #     continue
            print(f"[+] Processing {vuln_type}...")

            sinks_for_type = potential_sink_dict.get(vuln_type, [])
            if not sinks_for_type:
                print(f"[+] No sinks found for vulnerability type {vuln_type}")
                continue
            
            print(f"\n[+] Processing vulnerability type {vuln_type}...")
            print(f"[+] Total sinks to process: {len(sinks_for_type)}")
            print(f"[+] Timeout per sink: {TIMEOUT_SECONDS}s")
            print(f"[+] Max concurrent workers: {num_workers}")
            
            # 
            final_sink_context['inter'][vuln_type] = {}
            
            # 
            total_processed = 0
            total_timeout = 0
            total_error = 0
            total_success = 0
            
            #  process_single_sink_with_timeout 
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                # 
                future_to_sink = {
                    executor.submit(
                        process_single_sink_with_timeout,
                        sink,
                        target,
                        potential_source,
                        TIMEOUT_SECONDS
                    ): sink
                    for sink in sinks_for_type
                }
                
                # 
                for future in tqdm(
                    as_completed(future_to_sink),
                    total=len(future_to_sink),
                    desc=f"Type {vuln_type}"
                ):
                    sink = future_to_sink[future]
                    total_processed += 1
                    
                    try:
                        node_id, contexts, dataflow = future.result()
                        
                        # 
                        if not contexts and not dataflow:
                            total_timeout += 1
                        else:
                            total_success += 1
                        
                        # 
                        final_sink_context['inter'][vuln_type][node_id] = contexts
                        if dataflow:  #  dataflow
                            final_dataflow_str_list['inter'].append(dataflow)
                        
                    except Exception as e:
                        total_error += 1
                        print(f"\n[-] Exception processing sink {sink.node_id}: {e}")
                        #  sink
                        final_sink_context['inter'][vuln_type][sink.node_id] = {}
            
            # 
            print(f"\n[+] Vulnerability type {vuln_type} processing complete:")
            print(f"    - Total processed: {total_processed}")
            print(f"    - Successful: {total_success}")
            print(f"    - Timeout/Failed: {total_timeout}")
            print(f"    - Errors: {total_error}")

    
    except Exception as e:
        print(f"\n[-] Error during sink processing: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        print("[+] Stopping Neo4j database...")
        stop_database_with_port(target, detection_inter_slice_result_neo4j_dir)
    
    
    # 
    print("\n[+] Saving results...")
    try:
        with open(target_detection_inter_slice_result_signature_path, "w", encoding="utf-8") as f:
            json.dump(final_sink_context, f, ensure_ascii=False, indent=4)
        print(f"[+] Sink contexts saved to: {target_detection_inter_slice_result_signature_path}")
        
        with open(target_detection_inter_slice_result_dataflow_str_path, "w", encoding="utf-8") as f:
            json.dump(final_dataflow_str_list, f, ensure_ascii=False, indent=4)
        print(f"[+] Dataflow strings saved to: {target_detection_inter_slice_result_dataflow_str_path}")
        
    except Exception as e:
        print(f"[-] Error saving results: {e}")
        return False
    
    print("\n" + "="*60)
    print("sink ")
    print("="*60 + "\n")
    
    return True



def init_worker():
    """ SIGINT  KeyboardInterrupt """
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def process_single_sink_with_timeout(sink, target, potential_source, timeout_seconds):
    """
     sink 
    
    Args:
        sink: potential_sink 
        target: 
        potential_source:  source 
        timeout_seconds: 
        
    Returns:
        tuple: (node_id, contexts_dict, dataflow_dict)  (node_id, {}, {}) 
    """
    manager = Manager()
    result_queue = manager.Queue()
    
    def worker():
        """"""
        try:
            result = process_single_sink(sink, target, potential_source)
            result_queue.put(('success', result))
        except Exception as e:
            result_queue.put(('error', str(e)))
    
    # 
    process = Process(target=worker)
    process.start()
    process.join(timeout=timeout_seconds)
    
    # 
    if process.is_alive():
        # 
        print(f"\n[-] Process for sink {sink.node_id} timeout, terminating...")
        process.terminate()
        process.join(timeout=5)
        
        #  terminate  kill
        if process.is_alive():
            process.kill()
            process.join()
        
        return sink.node_id, {}, {}
    
    # 
    if not result_queue.empty():
        status, data = result_queue.get()
        if status == 'success':
            return data
        else:
            print(f"\n[-] Error in worker for sink {sink.node_id}: {data}")
            return sink.node_id, {}, {}
    
    # 
    return sink.node_id, {}, {}


def process_single_sink(sink, target, potential_source):
    """
     -  sink
     pickle 
    
    Args:
        sink: potential_sink 
        target: 
        potential_source:  source 
        
    Returns:
        tuple: (node_id, contexts_dict, dataflow_dict)
    """
    node_id = sink.node_id
    
    # 
    if sink.func_name in {"preg_replace", "array_map"}:
        return node_id, {}, {}
    
    try:
        config_dict = {
            "all_prepatch": {
                "NEO4J_HOST": "localhost",
                "NEO4J_PORT": "7687",
                "NEO4J_USERNAME": "neo4j",
                "NEO4J_PASSWORD": "password",
                "NEO4J_DATABASE": "neo4j",
                "NEO4J_PROTOCOL": "bolt"
            }
        }
        #  Neo4j 
        analyzer_target = Neo4jEngine.from_dict(config_dict["all_prepatch"])
        
        # 
        context_slicer = ContextSlicerSig(
            anchor_node=sink,
            analyzer=analyzer_target,
            custom_sources=potential_source
        )
        
        # 
        contexts = []
        context_series = context_slicer.run()
        
        for path, condition_ids in context_series:
            args_expr, conds = get_expression_and_conditions(
                analyzer_target, path, condition_ids
            )
            contexts.append(list(set(args_expr)))
        
        #  sink 
        sink_file = analyzer_target.fig_step.get_belong_file(
            analyzer_target.get_node_itself(sink.node_id)
        )
        
        return (
            node_id,
            {sink_file: contexts},
            {sink_file: context_slicer.dataflow_str_list}
        )
        
    except Exception as e:
        print(f"[-] Error processing sink node {node_id}: {e}")
        import traceback
        traceback.print_exc()
        return node_id, {}, {}
    
    finally:
        # 
        pass


if __name__ == '__main__':
    import argparse

    DATABASE_PATH = "../detection_projects_neo4j_800_900/"
    parser = argparse.ArgumentParser(description="Multi-database parallel processing")
    parser.add_argument('--num-workers', type=int, default=64, help='Number of worker threads')
    parser.add_argument('--num-neo4j-instances', type=int, default=4, help='Number of Neo4j instances')
    parser.add_argument('--database-path', type=str, default=DATABASE_PATH, help='Path to the Neo4j databases')
    parser.add_argument('--target-repo', type=str, default="", help='Target repository name (optional)')
    args = parser.parse_args()
    NUM_WORKERS = args.num_workers
    NUM_NEO4J_INSTANCES = args.num_neo4j_instances
    DATABASE_PATH = args.database_path

    STAR_RANGE = "_".join(os.path.basename(os.path.abspath(DATABASE_PATH)).split("_")[3:])
    if args.target_repo:
        print(f"[+] Processing only target repository: {args.target_repo}")
        TARGET_REPO = args.target_repo
    else:
        TARGET_REPO = ""

    print(f"[+] Configuration:")
    print(f"    Worker threads: {NUM_WORKERS}")
    print(f"    Neo4j instances: {NUM_NEO4J_INSTANCES}")
    print(f"    Threads per instance: ~{NUM_WORKERS // NUM_NEO4J_INSTANCES}")
    print(f"    Database path: {DATABASE_PATH}")
    print(f"    Star range: {STAR_RANGE}")
    print(f"    Target repo: {TARGET_REPO if TARGET_REPO else 'All repos'}")
    print()
    main()