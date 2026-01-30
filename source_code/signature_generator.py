# 有两种方式可以生成签名，一种是通过读取 cve 信息，然后通过 patch 来自动生成。另一种是通过手动指定的 cve 信息来自动生成签名。

import os
import subprocess
import json
import time
import concurrent
from hydra_utils import *
from tqdm import tqdm
import shutil
import traceback
from typing import Dict, List
from datetime import datetime
import concurrent
from config import DATA_INPUT_PATH, DATABASE_PATH, STORAGE_PATH, GIT_URL_DICT, NEO4j_PATH, NEO4j_POST_PATH, NEO4J_CONFIGURE_MAP_PATH
from core.patch_analyzer import PatchAnalyzer
from core.cve_sink_finder import CVESinkFinder
from core.cve_sink_finder_sig import CVESinkFinderSig
from core.anchor_node_matcher import AnchorNodeMatcher
from core.target_sink_finder import TargetSinkFinder
from core.context_slicer import ContextSlicer
from core.context_slicer_sig import ContextSlicerSig
from core.neo4j_connector_center import Neo4jConnectorCenter
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.signature_matcher import SignatureMatcher
from core.helper import get_expression_and_conditions, StringFilter
from core.chat import openai_chat
from core.forward_slice import InterproceduralForwardSlicer
from core.intro_to_inter_llm import inter_to_intra_chat, source_sink_slice_fix_and_merge
from core.anchor_node import AnchorNode
from pydriller import Commit, Git
from concurrent.futures import ThreadPoolExecutor, as_completed


repo_dir = "./rcs_meta/repository_cache"
PROJECTS_DIR = "./projects"
PROJECTS_NEO4J_DIR = "./projects_neo4j"
PATCH_ANALYSIS_CACHE_DIR = "./intermediate_results/sig_from_patch"
MANUAL_ANALYSIS_CACHE_DIR = "./intermediate_results/sig_from_manual"
sig_generate_dir = "./sig_gene_results"
sig_generate_slice_result = "./sig_gene_results/slice_results"
sig_generate_slice_result_neo4j = "./sig_gene_results/slice_results_neo4j"
neo4j_config_path = "./config/neo4j_siggene.json"


variant_sig_generate_slice_result_neo4j = "./sig_gene_results/variant_results_neo4j"

VULN_TYPE_STR_TO_DIGIT_DICT = {
    "XSS": 10,
    "sql_injection" : 9,
    "command_injection": 4,
    "code_injection": 3,
    "file_inclusion": 7,
    "file_upload": 6,
    "deserialization": 8,
}



VULN_TYPE_DICT = {
    7: 'File Include',
    2: 'File Read',
    1: 'File Delete',
    12: 'File Write',
    10: 'XSS',
    4: 'Command Injection',
    3: 'Code Injection',
    6: 'File Upload',
    13: 'Open Redirect',
    8: 'PHP Object Injection',
    9: 'SQL Injection'
}


def get_vuln_commit(repo_name, commit_hash):
    if os.path.exists(os.path.join(PROJECTS_NEO4J_DIR, f"{repo_name}-{commit_hash}_prepatch")):
        print(f"[+] {repo_name} at commit {commit_hash} already exists in projects_neo4j dir.")
        return os.path.join(PROJECTS_DIR, f"{repo_name}-{commit_hash}_prepatch"), os.path.join(PROJECTS_DIR, f"{repo_name}-{commit_hash}_postpatch")

    if os.path.exists(os.path.join(PROJECTS_DIR, f"{repo_name}-{commit_hash}_prepatch")):
        local_repo_path = os.path.join(repo_dir, repo_name.lower())
        pd_git = Git(local_repo_path)
        cmt = pd_git.get_commit(commit_hash)
        parent_hash = cmt.parents[0]
        print(f"[+] Found parent commit: {parent_hash}")
        print(f"[+] {repo_name} at commit {commit_hash} already exists in projects dir.")
        return os.path.join(PROJECTS_DIR, f"{repo_name}-{commit_hash}_prepatch"), os.path.join(PROJECTS_DIR, f"{repo_name}-{commit_hash}_postpatch")

    os.environ["HEAP"] = "3G"

    local_repo_path = os.path.join(repo_dir, repo_name.lower())
    if not os.path.exists(local_repo_path):
        return False, "repo_not_exist"
        if not clone_repo(repo_name):
            return False, "clone_repo"

    # 取得 parent commit
    pd_git = Git(local_repo_path)
    try:
        cmt = pd_git.get_commit(commit_hash)
    except Exception as e:
        print(f"[!] Skipping commit {commit_hash} due to could not be resolved: {e}")
        return False, "commit_miss"
    if not cmt.parents:
        print(f"[!] Commit {commit_hash} has no parent.")
        return False, "no_parent"
    parent_hash = cmt.parents[0]
    print(f"[+] Found parent commit: {parent_hash}")
    pd_git.checkout(commit_hash)
    target_dir = os.path.join(PROJECTS_DIR, f"{repo_name}-{commit_hash}_postpatch")
    if os.path.exists(target_dir):
        print(f"[+] {target_dir} already exists. skip copying...")
    else:
        try:
            shutil.copytree(local_repo_path, target_dir, dirs_exist_ok=True)
        except Exception as e:
            print(f"[-] Error copying to {target_dir}: {e}")
            return False, "copy_error"
    target_dir1 = target_dir

    pd_git.checkout(parent_hash)
    target_dir = os.path.join(PROJECTS_DIR, f"{repo_name}-{commit_hash}_prepatch")
    if os.path.exists(target_dir):
        print(f"[+] {target_dir} already exists. skip copying...")
    else:
        try:
            shutil.copytree(local_repo_path, target_dir, dirs_exist_ok=True)
        except Exception as e:
            print(f"[-] Error copying to {target_dir}: {e}")
            return False, "copy_error"

    print(f"[+] Processing repo {repo_name} at commit {commit_hash} ")
    print(f"parent {parent_hash}")
    print("[+] processing done.")
    return target_dir, target_dir1


from func_timeout import func_timeout, FunctionTimedOut

def llm_find_potential_sink(potential_sink_funcname: set, model="gpt-4") -> List[str]:
    try:
        return func_timeout(240, _inner_llm_find_potential_sink, args=(potential_sink_funcname, model, ))
    except FunctionTimedOut:
        print("Timeout! Returning empty.")
        return []


def _inner_llm_find_potential_sink(potential_sink_funcname: set, model) -> List[str]:

    prompt = """
### Task:
You are a senior PHP expert. Your task is to identify APIs and function calls that are related to database operations. Using your existing knowledge of PHP frameworks and third-party libraries, together with the semantics of the provided functions and methods, determine which of those calls directly perform database actions or act as wrappers for database interfaces (including native interfaces, third-party libraries, and custom wrappers). Follow the steps sequentially and return only the function-call APIs that satisfy all the given conditions.

### Think step by step:
Step 1: First, identify the following categories of function calls:
a. PHP built-in database interfaces
e.g., mysqli_query, mysqli_connect, PDO::query, etc.

b. Third-party library database interfaces
e.g., $conn->executeQuery, DB::select(), etc.

c. Encapsulated functions/methods for database operations
e.g., $db->query(), query(), fetchRow(), numsRow() which may internally call SQL operations.

Step 2: From the identified function calls, Exclude and do not return any API or function call if it matches any of the following:
1. If the API involves ORM entity-level operations(e.g., $user->save(); User::find(1); User::where('email', $email)->exists(); DB::table("item_tag")->insertGetId() etc.) then exclude it.
2. If the API uses any form of query-builder–style SQL construction (e.g., $query = DB::table('users')->where('id', 1)->get();) then exclude it.
3. Exclude any API that uses prepare-style database operations where only a partial or incomplete SQL chain is visible (e.g., $pdo->prepare(...)->execute() with an SQL fragment). Only APIs that execute a complete SQL statement directly should be considered.
4. Exclude any API that performs parameterized SQL queries, as these represent parameterized statements rather than direct SQL execution.
5. If the database-related behavior of the API cannot be determined with sufficient confidence, then exclude it — do not guess or infer beyond clear evidence.

### Input
{call_expr}

### Output Requirements
Please output a list of the methods/functions that meet the criteria, wrapped in an XML tag `<answer>`. Keep your thoughts in mind, but don't show them in the output.

### Output 
<answer>[ ]</answer>
"""
    # prompt_all_callsite = "\n".join(
    #         [f"callsite {index + 1}: {code}" for index, code in enumerate(list(potential_sink_funcname))]
    #     )
    prompt = prompt.format(call_expr=potential_sink_funcname)

    response = openai_chat(prompt, temperature=0.1, model=model)
    print("LLM Response:", response)
    # Extract the answer from the response
    if "<answer>" in response and "</answer>" in response:
        answer = response.split("<answer>")[1].split("</answer>")[0].strip()
        print("Extracted Answer:", answer)

    # 把 answer 解析成 list
    custom_sink_funcname_list = set()
    if answer.startswith("[") and answer.endswith("]"):
        items = answer[1:-1].split(",")
        for item in items:
            item = item.strip().strip("'").strip('"')
            if item:
                custom_sink_funcname_list.add(item)

    return list(custom_sink_funcname_list)


def llm_find_potential_source(potential_source_funcname: set) -> List[str]:
    # TODO：  Input::get(page, 1) 这种比较迷惑  是不是需要弄下
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

    response = openai_chat(prompt, temperature=0.1, model="gpt-5")
    # print("LLM Response:", response)
    # Extract the answer from the response
    if "<answer>" in response and "</answer>" in response:
        answer = response.split("<answer>")[1].split("</answer>")[0].strip()
        print("Extracted Answer:", answer)


    # 把 answer 解析成 list
    # 这里提取也有点问题  Input::get(page, 1)  这种会被当成两个
    custom_sink_funcname_list = set()
    if answer.startswith("[") and answer.endswith("]"):
        items = answer[1:-1].split(",")
        for item in items:
            item = item.split('(')[0].strip().strip("'").strip('"')
            if item:
                custom_sink_funcname_list.add(item)

    return list(custom_sink_funcname_list)



def patch_analysis_with_cve(_map_key_1, _map_key_2, vuln_type, cve_id, fixing_file, slice_results):
    git_repository, __ = StringFilter.filter_map_key_to_git_repository_and_version(_map_key_1)
    commit_id = StringFilter.filter_normalized_commit_id(__)

    config_dict = json.load(open(neo4j_config_path, 'r'))[_map_key_1]
    analyzer_pre = Neo4jEngine.from_dict(config_dict)
    config_dict_2 = json.load(open(neo4j_config_path, 'r'))[_map_key_2]
    analyzer_post = Neo4jEngine.from_dict(config_dict_2)

    print("[ 2.0 ] 分析 patch ...")
    patch_analyzer = PatchAnalyzer(analyzer_pre, analyzer_post,
                                   commit_url=GIT_URL_DICT[git_repository.lower()] + '/commit/' + commit_id,
                                   commit_id=commit_id, cve_id=cve_id, fixing_file=fixing_file)
    patch_analyzer.run_result()
    # config_level 决定 callee depth 的深度  这里已经失效了
    default_config_level, is_find_flag = 1, False
    anchor_node_list = []
    start_time1 = time.time()

    # 找 sink

    print("[ 2.1 ] 根据 patch 寻找 sink ...")
    print("[+] 查找缓存是否处理过 ...")
    potential_sink_funcname_list_json = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "potential_sink_funcname_list.json")
    if not os.path.exists(potential_sink_funcname_list_json):
        with open(potential_sink_funcname_list_json, 'w') as f:
            json.dump({}, f)
    with open(potential_sink_funcname_list_json, 'r') as f:
        potential_sink_funcname_data = json.load(f)


    vt_key = str(vuln_type)
    potential_sink_funcname_list = None

    # initialize list for this vuln type if missing
    if vt_key not in potential_sink_funcname_data:
        potential_sink_funcname_data[vt_key] = []

    # try to find existing record for this cve+commit
    existing_entry = next(
        (e for e in potential_sink_funcname_data[vt_key]
         if str(e.get('commit_id')) == str(commit_id) and str(e.get('cve_id')) == str(cve_id)),
        None
    )
    print("[+] 缓存中不存在，开始查找 sink ...")
    potential_anchor_finder = CVESinkFinder(analyzer_pre,
                                        commit_id=commit_id,
                                        vuln_type=vuln_type,
                                        git_repository=git_repository,
                                        config_level=default_config_level,
                                        cve_id=cve_id,
                                        custom_sinks=["$db->exec"],
                                        max_caller_depth=2, max_callee_depth=2)
    is_find_flag = potential_anchor_finder.traversal()

    if existing_entry is not None:
        potential_sink_funcname_list = existing_entry.get('potential_sink_funcname_list', [])
        print(f"[+] Found cached potential sinks for vuln_type={vt_key}, commit={commit_id}: {potential_sink_funcname_list}")
        # 已经处理过但没有 sink
        if len(potential_sink_funcname_list) == 0:
            print("[-] 缓存中存在且为空，说明处理过没有找到，跳过当前 cve...")
            return 0, 0

    # os.makedirs(slice_dir, exist_ok=True)

    else:
        print("[+] 缓存中不存在，开始查找 sink ...")

        # if vuln_type != 9:
        if True:
            nodes = potential_anchor_finder.potential_anchor_nodes
            if not nodes:
                # 保存空记录表示已经处理且无 sink
                entry = {
                    'cve_id': cve_id,
                    'commit_id': commit_id,
                    'potential_sink_funcname_list': []
                }
                potential_sink_funcname_data[vt_key].append(entry)
                with open(potential_sink_funcname_list_json, 'w') as f:
                    json.dump(potential_sink_funcname_data, f, indent=4)
                print("[-] 没有找到任何 sink 节点 !!!")
                return 0, 0
            else:
                # 其他类型的漏洞找到了预定义的 sink
                potential_sink_funcname_list = list(set([node.func_name for node in nodes]))
                print(f"[+] Statically find {len(potential_sink_funcname_list)} builtin potential sinks.")
                entry = {
                    'cve_id': cve_id,
                    'commit_id': commit_id,
                    'potential_sink_funcname_list': potential_sink_funcname_list
                }
                potential_sink_funcname_data[vt_key].append(entry)
                with open(potential_sink_funcname_list_json, 'w') as f:
                    json.dump(potential_sink_funcname_data, f, indent=4)

        end_time1 = time.time()
        print(f"[+] First round traversal time cost: {end_time1 - start_time1:.2f}s")
        
        # 只有 sql 注入需要 llm 帮忙找 sink
        # if (potential_sink_funcname_list is None or len(potential_sink_funcname_list) == 0) and vuln_type == 9:
        # 无论是否是内置的  都用 llm 来辅助判断一遍
        if vuln_type == 9:
            potential_sink_funcname_list = llm_find_potential_sink(potential_anchor_finder.potential_sink_funcname)

            if not potential_sink_funcname_list:
                entry = {
                    'cve_id': cve_id,
                    'commit_id': commit_id,
                    'potential_sink_funcname_list': []
                }
                potential_sink_funcname_data[vt_key].append(entry)
                with open(potential_sink_funcname_list_json, 'w') as f:
                    json.dump(potential_sink_funcname_data, f, indent=4)
                print("[-] 借助 LLM 也没有找到任何 sink 节点 !!!")
                return 0, 0
            print(f"[+] LLM find {len(potential_sink_funcname_list)} potential sinks: {potential_sink_funcname_list}")
            entry = {
                'cve_id': cve_id,
                'commit_id': commit_id,
                'potential_sink_funcname_list': potential_sink_funcname_list
            }
            potential_sink_funcname_data[vt_key].append(entry)
            with open(potential_sink_funcname_list_json, 'w') as f:
                json.dump(potential_sink_funcname_data, f, indent=4)

    if not potential_sink_funcname_list:
        print("[-] 最终没有找到任何 sink 节点 !!!")
        return 0, 0
    
    print("[ 2.2 ] 找到潜在的 sink， 开始进行 patch-to-sink 切片 ...")
    # 对前面收集的 call path 进行过滤，只保留包含潜在 sink 的路径
    slicer = InterproceduralForwardSlicer(analyzer_pre)
    slice_dir = slice_results
    patch_sink_paths = filter_patch_sink_paths(potential_anchor_finder.all_paths, potential_sink_funcname_list)
    # 这里执行的是跨过程切片，如果没有跨过程，则 callsite_function_dict 和 call_path_patch_node 都是空的
    slice_dir_ps = os.path.join(slice_dir, "patch_to_sink")
    if os.path.exists(slice_dir_ps) and len(os.listdir(slice_dir_ps)) > 0:
        print(f"[+] {os.path.join(slice_dir, 'patch_to_sink')} already exists. skip patch_to_sink slicing ...")
    else:
        os.makedirs(slice_dir_ps, exist_ok=True)
        callsite_function_dict = {} # call_path_idx: func_id
        for idx, call_path in enumerate(potential_anchor_finder.all_paths):
            callsite_node = call_path[0]
            callsite_function_node_id = analyzer_pre.get_node_itself(callsite_node['call_site_nodeid'])[NODE_FUNCID]
            callsite_function_dict[idx] = callsite_function_node_id

        call_path_patch_node = {}
        for file, affected_line in potential_anchor_finder.patch_analysis_result.items():
            for affect_node in affected_line:
                affect_neo4j_node = analyzer_pre.get_node_itself(affect_node.root_node) 
                func_id = affect_neo4j_node[NODE_FUNCID]
                
                for idx, callsite_func_id in callsite_function_dict.items():
                    if idx not in call_path_patch_node:
                        call_path_patch_node[idx] = []
                    if func_id == callsite_func_id:
                        patch_node_info = {
                            "call_site_nodeid": affect_neo4j_node[NODE_INDEX],
                            "call_site_code": "patch_statement",
                            "callee_name": "patch_callee",
                            "param_name": "patch_param",
                            "param_pos": 0,
                            "taint_var": "patch_var",
                            "depth": 0,
                            "location": {"line": affect_neo4j_node[NODE_LINENO],
                                        "file": analyzer_pre.fig_step.get_belong_file(affect_neo4j_node)
                                    }
                        }
                        call_path_patch_node[idx].append(patch_node_info)                

        os.makedirs(slice_dir_ps, exist_ok=True)
        
        # 先判断是否是跨过程的，如果不是则直接按照 patch 切
        # TODO 切片这里还有问题：一是前面 traversal 的时候需要记录 funcid 才可以，二是做改写，和下面的逻辑一样
        if potential_anchor_finder.all_paths.__len__() == 0:    # 
            patch_staments = []
            for file, affected_line in potential_anchor_finder.patch_analysis_result.items():
                for affect_node in affected_line:
                    affect_neo4j_node = analyzer_pre.get_node_itself(affect_node.root_node) 
                    patch_node_info = {
                        "call_site_nodeid": affect_neo4j_node[NODE_INDEX],
                        "call_site_code": "patch_statement",
                        "callee_name": "patch_callee",
                        "param_name": "patch_param",
                        "param_pos": 0,
                        "taint_var": "patch_var",
                        "depth": 0,
                        "location": {"line": affect_neo4j_node[NODE_LINENO],
                                    "file": analyzer_pre.fig_step.get_belong_file(affect_neo4j_node)
                                }
                        }
                    patch_staments.append(patch_node_info)
            # 1. 执行切片 获取 node_id list
            slice_result = slicer.forward_slice_intra(patch_statements=patch_staments)
            # 2. 导出代码
            code_output = slicer.export_slice_code(slice_result, output_file=f"{slice_dir_ps}/ps_path_0.php")
            # print(code_output)
            print(f"[+] Export slice code to {slice_dir_ps}/ps_path_0.php")

        else:
            for idx, call_path in enumerate(potential_anchor_finder.all_paths):
                if idx in call_path_patch_node:
                # 1. 执行切片 获取 node_id list
                    slice_result = slicer.forward_slice(call_path, patch_statements=call_path_patch_node[idx])

                    # 2. 导出代码
                    code_output = slicer.export_slice_code(slice_result, output_file=f"{slice_dir_ps}/ps_path_{idx}.php")
                    # print(code_output)
                    print(f"[+] Export slice code to {slice_dir_ps}/ps_path_{idx}.php")


    # 找 source
    print("[ 2.3 ] 找到潜在的 sink，开始寻找潜在的 source ...")
    end_time = time.time()
    print("[+] Patch analysis for SOURCE location ...")
    example_node = potential_anchor_finder.patch_analysis_result[list(potential_anchor_finder.patch_analysis_result.keys())[0]][0].root_node
    affect_neo4j_node = analyzer_pre.get_node_itself(example_node)

    anchor_node = AnchorNode.from_node_instance(
                        affect_neo4j_node, judge_type=0, git_repository="",
                        version="prepatch",
                        func_name="", param_loc=-1,
                        file_name="",
                        cve_id=""
                )
    signature_generator = ContextSlicer(anchor_node=anchor_node, analyzer=analyzer_pre, commit_id=commit_id, cve_id=cve_id, vuln_type=vuln_type)
    signature_series = signature_generator.run()

    # 这里要处理一下 全局变量 sources 和 source function call 的关系
    potential_source_funcname_list_json = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "potential_source_funcname_list.json")
    if not os.path.exists(potential_source_funcname_list_json):
        with open(potential_source_funcname_list_json, 'w') as f:
            json.dump({}, f)
    with open(potential_source_funcname_list_json, 'r') as f:
        potential_source_funcname_data = json.load(f)
    if cve_id in potential_source_funcname_data:
        potential_source_funcname_list = potential_source_funcname_data[cve_id]
        print(f"[+] Found potential source functions for {cve_id}: {potential_source_funcname_list}")
        if potential_source_funcname_list.__len__() == 0:
            print("[-] No source found in cache !!!")
            return 0, 0
    else:
        potential_source_funcname_list = signature_generator.potential_source_funcname
        llm_find_source = False
        if potential_source_funcname_list:
            print(f"[+] Found {potential_source_funcname_list.__len__()} potential funcname when find sources: {potential_source_funcname_list}")
            potential_source_funcname_list = llm_find_potential_source(potential_source_funcname_list)
            if not potential_source_funcname_list:
                print("[-] Cannot find any source function with LLM !!!")
                potential_source_funcname_data[cve_id] = []
                with open(potential_source_funcname_list_json, 'w') as f:
                    json.dump(potential_source_funcname_data, f)
            else:
                llm_find_source = True
                print(f"[+] LLM find {potential_source_funcname_list.__len__()} potential sources: {potential_source_funcname_list}")
                potential_source_funcname_data[cve_id] = potential_source_funcname_list
                with open(potential_source_funcname_list_json, 'w') as f:
                    json.dump(potential_source_funcname_data, f)
        
        if signature_generator.sources.__len__() == 0:
            print("[-] No buildin source found in backward slicing !!!")
            if not llm_find_source:
                return 0, 0
        else:
            print(f"[+] Found {signature_generator.sources.__len__()} built in sources in backward slicing: {signature_generator.sources}")
            if cve_id in potential_source_funcname_data:
                potential_source_funcname_data[cve_id].append("builtin_source")
                with open(potential_source_funcname_list_json, 'w') as f:
                    json.dump(potential_source_funcname_data, f)



    print("[ 2.4 ] 找到潜在的 source， 开始进行 source-to-patch 切片 ...")
    # 对前面收集的 call path 进行过滤，只保留包含潜在 source 的路径
    patch_source_paths = filter_patch_sink_paths(signature_generator.backward_call_paths, potential_source_funcname_list)

    
    slice_dir_sp = os.path.join(slice_dir, "source_to_patch")
    if os.path.exists(slice_dir_sp) and len(os.listdir(slice_dir_sp)) > 0:
        print(f"[+] {os.path.join(slice_dir, 'source_to_patch')} already exists. skip source_to_patch slicing ...")
    else:
        # 第i条调用路径的起始点所属的 function id
        slicer = InterproceduralForwardSlicer(analyzer_pre, "sp")
        source_patch_callsite_function_dict = {} # call_path_idx: func_id
        for idx, call_path in enumerate(signature_generator.backward_call_paths):
            call_path = slicer.convert_backward_to_forward(call_path)
            callsite_node = call_path[0]
            callsite_function_node_id = analyzer_pre.get_node_itself(callsite_node['call_site_nodeid'])[NODE_FUNCID]
            source_patch_callsite_function_dict[idx] = callsite_function_node_id

        source_patch_call_path_patch_node = {}
        for file, affected_line in potential_anchor_finder.patch_analysis_result.items():
            for affect_node in affected_line:
                affect_neo4j_node = analyzer_pre.get_node_itself(affect_node.root_node) 
                func_id = affect_neo4j_node[NODE_FUNCID]

                for idx, callsite_func_id in source_patch_callsite_function_dict.items():
                    if idx not in source_patch_call_path_patch_node:
                        source_patch_call_path_patch_node[idx] = []
                    # if func_id == callsite_func_id:
                        patch_node_info = {
                            "call_site_nodeid": affect_neo4j_node[NODE_INDEX],
                            "call_site_code": "patch_statement",
                            "callee_name": "patch_callee",
                            "param_name": "patch_param",
                            "param_pos": 0,
                            "taint_var": "patch_var",
                            "depth": 0,
                            "location": {"line": affect_neo4j_node[NODE_LINENO],
                                        "file": analyzer_pre.fig_step.get_belong_file(affect_neo4j_node)
                                    }
                        }
                        source_patch_call_path_patch_node[idx].append(patch_node_info)

        os.makedirs(slice_dir_sp, exist_ok=True)
        
        patch_staments = []
        for file, affected_line in potential_anchor_finder.patch_analysis_result.items():
            for affect_node in affected_line:
                affect_neo4j_node = analyzer_pre.get_node_itself(affect_node.root_node) 
                patch_node_info = {
                    "call_site_nodeid": affect_neo4j_node[NODE_INDEX],
                    "call_site_code": "patch_statement",
                    "callee_name": "patch_callee",
                    "param_name": "patch_param",
                    "param_pos": 0,
                    "taint_var": "patch_var",
                    "depth": 0,
                    "location": {"line": affect_neo4j_node[NODE_LINENO],
                                "file": analyzer_pre.fig_step.get_belong_file(affect_neo4j_node)
                            }
                    }
                patch_staments.append(patch_node_info)

        for idx, call_path in enumerate(signature_generator.backward_call_paths):

            call_relateions = []
            new_call_path = slicer.convert_backward_to_forward(call_path)

            if ss_in_inter(call_path):
                call_relateions = extract_adjacent_relations(call_path)
                slice_result = slicer.forward_slice_source_patch(new_call_path, source_patch_call_path_patch_node[idx])

                print(f"[+] Source and sink are in different functions for sink node {anchor_node.node_id}.")
                output_file = f"{slice_dir_sp}/src_sink_path_{idx}_inter.php"

            else:
                print(f"[+] Source and sink are in the same function for sink node {anchor_node.node_id}.")
                # 1. 执行切片 获取 node_id list
                slice_result = slicer.forward_slice_intra(patch_statements=patch_staments)
                output_file = f"{slice_dir_sp}/src_sink_path_{idx}_intra.php"
                

            if os.path.exists(output_file):
                print(f"[+] {output_file} already exists. skip slicing ...")
                continue
            code_output = slicer.export_slice_code(slice_result, output_file, call_relateions)
            print(f"[+] Export slice code to {output_file}")

    print("[ 2.5 ] 找到 sink 和 source，且对 source-to-patch 和 patch-to-sink 分别切片完成，可以合成 source-to-sink ...")
    inter_to_intra_dir = os.path.join(slice_dir, "inter_to_intra")
    if os.path.exists(inter_to_intra_dir) and len(os.listdir(inter_to_intra_dir)) > 0:
        print(f"[+] {os.path.join(slice_dir, 'inter_to_intra')} already exists. skip inter_to_intra generation ...")
    else:
        os.makedirs(inter_to_intra_dir, exist_ok=True)
        for sp_idx, sp_slice in enumerate(os.listdir(slice_dir_sp)):
            with open(os.path.join(slice_dir_sp, sp_slice), 'r') as f:
                sp_code = f.read()
            for ps_idx, ps_slice in enumerate(os.listdir(slice_dir_ps)):
                with open(os.path.join(slice_dir_ps, ps_slice), 'r') as f:
                    ps_code = f.read()
                combined_code = f"Source to Patch Code:\n{sp_code}\n\nPatch to Sink Code:\n{ps_code}\n" 
                source_sink_slice_fix_and_merge(", ".join(potential_source_funcname_list), 
                                    ", ".join(potential_sink_funcname_list),
                                    combined_code, inter_to_intra_dir, f"{sp_idx}_{ps_idx}")

    print("[ 2.6 ] 合成 source-to-sink 切片完成，开始导入 neo4j ...")
    if os.path.exists(os.path.join(sig_generate_slice_result_neo4j, cve_id)):
        print(f"[+] {os.path.join(sig_generate_slice_result_neo4j, cve_id)} already exists. skip importing to neo4j ...")
    else:
        repo_to_neo4j_cpg(inter_to_intra_dir, sig_generate_slice_result_neo4j)

    return potential_source_funcname_list, potential_sink_funcname_list


def cve_analysis(_map_key_1, vuln_type: int, cve_id: str, source_info: dict, sink_info: dict, ss_depth: dict):
    from core.cve_sink_finder_1201 import CVESinkFinder as CVESinkFinder_1201
    default_dir = sig_generate_slice_result
    git_repository, __ = StringFilter.filter_map_key_to_git_repository_and_version(_map_key_1)
    config_dict = json.load(open(neo4j_config_path, 'r'))[_map_key_1]
    analyzer_pre = Neo4jEngine.from_dict(config_dict)

    start_time = time.time()
    # 找 sink
    potential_anchor_finder = CVESinkFinder_1201(analyzer_pre,
                                            vuln_type=vuln_type,
                                            git_repository=git_repository,
                                            cve_id=cve_id,
                                            max_caller_depth=1,
                                            max_callee_depth=1,
                                            source_info=source_info,
                                            sink_info=sink_info)
    is_find_flag = potential_anchor_finder.traversal()
    
    anchornode_list = potential_anchor_finder.potential_anchor_nodes


    # 找 source
    slice_dir = os.path.join(default_dir, cve_id)
    for anchor_node in anchornode_list:
        signature_generator = ContextSlicer(
            anchor_node=anchor_node, 
            analyzer=analyzer_pre, 
            cve_id=cve_id, 
            vuln_type=vuln_type, 
            max_caller_depth=ss_depth.get('caller_depth', 1),
            max_callee_depth=ss_depth.get('callee_depth', 1)
        )

        # TODO 类内的 class 成员函数找不到数据流
        # $sql=mysql_query("select * from tb_admin where name='".$this->name."'",$conn); 
        # 对于类间属性的连接，后期再处理吧。
        # 例子是 cve-2020-18544  match (n) where n.id=214316 return n
        # 这个节点是 class 节点，他的子节点有一个 AST_TOPLEVEL 节点。这个节点里面才记录了类属性之类的，后面看这种情况多不多  多的话算是 implementation 中的一个贡献了，
        # 思路就是可以维护一个类属性到变量的映射表，然后在数据流中进行连接

        signature_series = signature_generator.run("DETECTION")

        potential_source_funcname_list = signature_generator.potential_source_funcname
        
        if source_info is None or source_info.get('function_name') in [None, "_POST", "_GET", "_REQUEST", "_FILE", "_COOKIE"]:
            if signature_generator.sources.__len__() == 0:
                print("[-] No source found in backward slicing !!!")
                continue

        else:
            if potential_source_funcname_list:
                print(f"[+] Found {potential_source_funcname_list.__len__()} potential sources: {potential_source_funcname_list}")
                for source_func in potential_source_funcname_list:
                    if source_func.split("(")[0] == source_info['function_name']:
                        print(f"[+] Found specified source function: {source_func}")
                        break
            else:
                print("[-] 给定了source信息但没有找到任何source函数 !!!")
                continue

        # 获取 call path 生成调用关系， 辅助LLM整合切片后的代码


        patch_source_paths = filter_source_sink_paths(signature_generator.backward_call_paths, [source_info['function_name']])

        if signature_generator.backward_call_paths.__len__() == 0:
            # 从 build-in 切？
            pass
        else:
            # 获得切片 and 获得签名
            # 对于过程内漏洞来说，直接获取原始签名。切片是为了获取代码然后变体用的
            slicer = InterproceduralForwardSlicer(analyzer_pre, direction="sp")
            slice_dir_sp = os.path.join(slice_dir, f"sink_{anchor_node.node_id}")
            os.makedirs(slice_dir_sp, exist_ok=True)
            
            merge_call_paths = merge_call_path(signature_generator.backward_call_paths)

            for idx, call_path in enumerate(merge_call_paths):
                # 归并 call paths
                # 因为目前的 call path 既包含了垂直的 call chain，也包含了水平的 call trace，因此需要在切片前归并. (已完成合并)

                # 过程内和过程间的 call path 要根据路径上的 funcid 区分，对于当前函数来说，call 了两个函数但是都没进入函数内，也算是函数内切片，但是 call path 也已经形成
                # 对于函数内和函数间要采取不同的切片方法
                call_relateions = []
                new_call_path = slicer.convert_backward_to_forward(call_path)
                if ss_in_inter(call_path):
                    output_file = f"{slice_dir_sp}/src_sink_path_{idx}_inter.php"

                    if os.path.exists(output_file):
                        print(f"[+] {output_file} already exists. skip slicing ...")
                        continue

                    call_relateions = extract_adjacent_relations(call_path)


                    slice_result = slicer.forward_slice_source_sink(new_call_path)
                    
                    print(f"[+] Source and sink are in different functions for sink node {anchor_node.node_id}.")

                else: # 过程内，就是正常的后向+前向切片 截至到 sink 之前，sink 之后的就不需要切了
                    # TODO：对于 source 前面可能还需要控制流的判断，如果有 check 截断也有必要判断。
                    output_file = f"{slice_dir_sp}/src_sink_path_{idx}_intra.php"
                    if os.path.exists(output_file):
                        print(f"[+] {output_file} already exists. skip slicing ...")
                        continue

                    slice_result = slicer.forward_slice_intra([new_call_path[-1]])
                    print(f"[+] Source and sink are in the same function for sink node {anchor_node.node_id}.")

                if os.path.exists(output_file):
                    print(f"[+] {output_file} already exists. skip slicing ...")
                    continue
                code_output = slicer.export_slice_code(slice_result, output_file, call_relateions)
                print(f"[+] Export slice code to {output_file}")

    new_code_flag = False
    # 经过LLM 将多过程的路径整合为过程内的。同时对代码进行语义恢复
    inter_to_intra_dir = os.path.join(slice_dir, "inter_to_intra")
    from core.intro_to_inter_llm import source_sink_slice_fix_and_merge, source_sink_slice_fix_only
    if os.path.exists(inter_to_intra_dir) and len(os.listdir(inter_to_intra_dir)) > 0:
        print(f"[+] {os.path.join(slice_dir, 'inter_to_intra')} already exists. skip inter_to_intra generation ...")
    else:
        os.makedirs(inter_to_intra_dir, exist_ok=True)
        
        # 这里拆分成两个 prompt，如果是过程内的 只做语义修复。如果是过程间的就做修复+整合
        for sink_dir in os.listdir(slice_dir):
            if not sink_dir.startswith("sink_"):
                continue
            slice_dir_sp = os.path.join(slice_dir, sink_dir)
            for src_sink_slice in os.listdir(slice_dir_sp):
                with open(os.path.join(slice_dir_sp, src_sink_slice), 'r') as f:
                    ss_code = f.read()
                new_code_flag = True
                idx = src_sink_slice.split("src_sink_path_")[-1].split(".php")[0]
                inter_flag = "_inter" in src_sink_slice
                if inter_flag: 
                    # LLM 修复 + 判断是否存在漏洞
                    source_sink_slice_fix_and_merge(", ".join([source_info.get('function_name')] if source_info else potential_source_funcname_list), ", ".join([sink_info['function_name']]), ss_code, inter_to_intra_dir, idx)
                else:
                    # LLM 只做修复
                    source_sink_slice_fix_only(ss_code, inter_to_intra_dir, idx)

    # 先 check，check不通过则移除当前目录，到 slice_merge_but_no_vuln 目录下
    from variant_agent import vuln_check
    for src_file in os.listdir(inter_to_intra_dir):
        result = vuln_check(cve_id, os.path.join(inter_to_intra_dir, src_file))
        if not result:
            print(f"[-] {src_file} does not contain the vulnerability after LLM processing. Moving to slice_merge_but_no_vuln directory.")
            os.makedirs(os.path.join(slice_dir, "slice_merge_but_no_vuln"), exist_ok=True)
            os.rename(os.path.join(inter_to_intra_dir, src_file), os.path.join(slice_dir, "slice_merge_but_no_vuln", src_file))


    print(f"[+] Patch analysis for {cve_id} completed, time cost: {time.time() - start_time:.2f}s\n 找到 sink 和 source 啦！！！")
    if os.path.exists(os.path.join(sig_generate_slice_result_neo4j, cve_id)):
        print(f"[+] {os.path.join(sig_generate_slice_result_neo4j, cve_id)} already exists. skip importing to neo4j ...")
    else:
        # 为 slice_dir 生成新的 neo4j cpg
        if os.listdir(inter_to_intra_dir).__len__() == 0:
            repo_to_neo4j_cpg(inter_to_intra_dir, sig_generate_slice_result_neo4j)

    return [source_info['function_name']], [sink_info['function_name']]


def pure_sink_generate_expr(potential_sink, analyzer_target: Neo4jEngine, custom_source, commit_id=None, cve_id=None):
    # 单纯的生成 sink 的表达式
    context_slicer = ContextSlicerSig(
        anchor_node=potential_sink,
        analyzer=analyzer_target,
        commit_id=commit_id, 
        cve_id=cve_id,
        custom_sources=custom_source
    )
    try:
        context_series = context_slicer.run()
        contexts = []
        for path, condition_ids in context_series:
            args_expr, conds = get_expression_and_conditions(analyzer_target, path, condition_ids)
            contexts.append(list(set(args_expr)))

        sink_file = analyzer_target.fig_step.get_belong_file(analyzer_target.get_node_itself(potential_sink.node_id))

        return potential_sink.node_id, contexts, {sink_file: context_slicer.dataflow_str_list}
    except Exception as e:
        print(f"[-] Error generating expression for sink node {potential_sink.node_id}: {e}")
        return potential_sink.node_id, [], {}



def run_sig_source_sink(target, potential_source, extend_vuln_model, task, cve_id=None, neoconfig_path=None, model=None):
    from core.anchor_node import AnchorNode
    print("[ 3.1 ]开始生成可以sink签名的表达式！！！！\n")

    if task == "sig":
        neo4j_config_path = "./config/neo4j_siggene.json"
        detection_inter_slice_result_neo4j_dir = sig_generate_slice_result_neo4j
        detection_inter_slice_result_signature_dir = os.path.join(sig_generate_dir, "signature_results", f"{cve_id}_sig_info")
        os.makedirs(detection_inter_slice_result_signature_dir, exist_ok=True)

    elif task == "variant":
        assert model is not None, "Model must be specified for variant task"
        neo4j_config_path = neoconfig_path
        detection_inter_slice_result_neo4j_dir = os.path.join(variant_sig_generate_slice_result_neo4j, model)
        detection_inter_slice_result_signature_dir = os.path.join(sig_generate_dir, "variant_signature_results", model, f"{cve_id}_variant_sig_info")
        os.makedirs(detection_inter_slice_result_signature_dir, exist_ok=True)


    target_detection_inter_slice_result_signature_path = os.path.join(detection_inter_slice_result_signature_dir, f"{target}_final_sink_context.json")
    
    target_detection_inter_slice_result_dataflow_str_path = os.path.join(detection_inter_slice_result_signature_dir, f"{target}_final_dataflow_str_list.json")

    if os.path.exists(target_detection_inter_slice_result_signature_path) and \
       os.path.exists(target_detection_inter_slice_result_dataflow_str_path):
        print(f"[+] Sink context and dataflow for {target} already exists. skip ... \n")
        stop_databases_w_database(os.path.join(detection_inter_slice_result_neo4j_dir, cve_id), cve_id)
        return True

    start_databases_with_database(os.path.join(detection_inter_slice_result_neo4j_dir, cve_id), f"{cve_id}_variant_sig_db")
    final_sink_context = dict()
    final_dataflow_str_list = dict()
    if os.path.exists(os.path.join(detection_inter_slice_result_neo4j_dir, cve_id)):

        change_neo4j_conf(target, target.replace("_prepatch", "_postpatch"), neo4j_config_path)

        config_dict = json.load(open(neo4j_config_path, 'r'))[target]
        analyzer_target = Neo4jEngine.from_dict(config_dict)
        final_sink_context['inter'] = {}
        final_dataflow_str_list['inter'] = []

        # try:
        sink_finder = TargetSinkFinder(analysis_framework=analyzer_target, git_repository=target)
        sink_finder.cc_run(extend_vuln_model)
        potential_sink_dict = sink_finder.potential_sinks        
        is_vulnerable = False
        MULTI_THREADING_ENABLED = True
        for vuln_type in VULN_TYPE_DICT.keys():
            print(f"\n[+] Processing {VULN_TYPE_DICT[vuln_type]}...\n")

            if MULTI_THREADING_ENABLED:
                with ThreadPoolExecutor(max_workers=18) as executor:
                    futures = [
                        executor.submit(
                            pure_sink_generate_expr, 
                            sink, analyzer_target, potential_source
                        )
                        for sink in potential_sink_dict.get(vuln_type, [])
                    ]

                    for future in tqdm(as_completed(futures), total=len(potential_sink_dict.get(vuln_type, []))):
                        node_id, contexts, file_dataflow_str_dict = future.result()
                        final_sink_context['inter'].setdefault(vuln_type, dict())
                        final_sink_context['inter'][vuln_type][node_id] = contexts
                        final_dataflow_str_list['inter'].append(file_dataflow_str_dict)
            else:
                for potential_sink in tqdm(potential_sink_dict.get(vuln_type, [])):
                    node_id, contexts, file_dataflow_str_dict = pure_sink_generate_expr(
                        potential_sink=potential_sink,
                        analyzer_target=analyzer_target,
                        custom_source=potential_source
                    )
                    final_sink_context['inter'].setdefault(vuln_type, dict())
                    final_sink_context['inter'][vuln_type][node_id] = contexts
                    final_dataflow_str_list['inter'].append(file_dataflow_str_dict)

        # except Exception as e:
        #     print(f"[-] Error during inter-slice processing for {target}: {e}")
        # finally:
        stop_databases_w_database(os.path.join(detection_inter_slice_result_neo4j_dir, cve_id), cve_id)
    
    # 保存结果
    with open(target_detection_inter_slice_result_signature_path, "w", encoding="utf-8") as f:
        json.dump(final_sink_context, f, ensure_ascii=False, indent=4)

    with open(target_detection_inter_slice_result_dataflow_str_path, "w", encoding="utf-8") as f:
        json.dump(final_dataflow_str_list, f, ensure_ascii=False, indent=4)
    
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {cve_id} 的签名和数据流提取完毕！")
    return True


def generate_signatures_from_patch(cve_info_file, target_cve=None):
    process_count_perbatch = 50
    cve_collection = json.load(fp=open(cve_info_file, 'r', encoding='utf-8'))

    already_built_neo4j_path = "./sig_generate_record/build_neo4j_all.json"

    ensure_skip_cve_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "ensure_skip_cve.json")
    with open(ensure_skip_cve_path, 'r', encoding='utf-8') as fp:
        ensure_skip_cve = list(json.load(fp))

    already_processed_cve_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "already_processed_cve.json")
    with open(already_processed_cve_path, 'r') as f:
        already_processed_cve = set(json.load(f))

    cpg_generate_timeout_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "cpg_generate_timeout.json")
    with open(cpg_generate_timeout_path, 'r') as f:
        cpg_generate_timeout_cve = set(json.load(f))

    # 对于已经处理过的 并且保存到了 /mnt hdd data 中的不再处理
    with open(already_built_neo4j_path, 'r') as f:
        already_built_neo4j = set(json.load(f))


    TIMEOUT = 600
    cve_id_to_vuln_type = dict()
    target_cve_flag = False
    with concurrent.futures.ThreadPoolExecutor() as executor:
        print("======================================================")
        print("=====   patch analysis: 分析已知漏洞 patch 信息   =====")
        print("======================================================")
        for vuln_type, cve_data in cve_collection.items():
            vuln_type_str = vuln_type

            if vuln_type in ["XSS"]:
                continue

            print(f"\nProcessing vulnerability type: {vuln_type_str}\n")

            for cve_id, cve_dict in tqdm(cve_data.items()):
                if cve_id not in cve_id_to_vuln_type:
                    cve_id_to_vuln_type[cve_id] = vuln_type_str
                
                if target_cve is not None and cve_id != target_cve:
                    target_cve_flag = True
                    continue


                process_count_perbatch -= 1
                if process_count_perbatch <= 0:
                    banner_print("[+] 本 batch 处理数量已达上限，提前结束，等待下一 batch 继续处理 ...")
                    break


                cve_repo = cve_dict['repo_name']
                vuln_type = VULN_TYPE_STR_TO_DIGIT_DICT[cve_dict['vuln_type']]
                commit_id = cve_dict['fixing_commit']
                fixing_file = cve_dict['fixing_files'][0]
                print(f"\n\nProcessing CVE: {cve_id}, Repo: {cve_repo}, Commit: {commit_id}")

                # 这部分还涉及到一个问题，就是由于内存不够，当前的 patch 生成是需要分批次进行的，有的 neo4j 已经生成但是被移动到了 /mnt
                # 所以这里可以进行一个判断，如果所需的 neo4j 已经存在于 /mnt 中的话，就不再重新生成，暂时直接跳过
                if cve_id in already_built_neo4j:
                    banner_print(f"[+] {cve_id} neo4j already built and saved to /mnt. skip ...")
                    continue

                if cve_id in already_processed_cve:
                    if not target_cve_flag:
                        banner_print(f"[+] {cve_id} already processed. skip ...")
                        continue

                if cve_id in ensure_skip_cve:
                    banner_print(f"[+] {cve_id} in ensure_skip_cve. skip ...")
                    continue

                if cve_id in cpg_generate_timeout_cve:
                    banner_print(f"[+] {cve_id} in cpg_generate_timeout_cve. skip ...")
                    continue

                intra_slice_results = os.path.join(sig_generate_slice_result, cve_id)  # 存放切片和LLM转义后的结果
                intra_slice_results_neo4j = os.path.join(sig_generate_slice_result_neo4j, cve_id)
                if os.path.exists(intra_slice_results_neo4j):
                    banner_print(f"[+] {cve_id} after slice neo4j already exists. skip ...")
                    continue

                banner_print(f"正式开始处理 {cve_id}")
                
                print("[ 0.  ] 搜索 hdd data cache ...")
                find_cve_in_hdd = False
                find_cve_in_hdd = search_cve_in_hdd_data_cache(cve_repo, commit_id)            
                if not find_cve_in_hdd:
                    print(f"[-] {cve_id} not found in hdd data cache. proceed to generate cpg ...")
                
                    vuln_repo_prepatch, vuln_repo_postpatch = get_vuln_commit(cve_repo, commit_id)
                    if vuln_repo_prepatch is False:
                        print(f"[!] Skipping {cve_id} due to error in getting vuln commit.")
                        continue

                    # 生成 cpg 并导入 neo4j
                    print("[ 1.  ] 生成 cpg 并导入 neo4j ...")
                    print(f"    processing {vuln_repo_prepatch} ...")
                    future = executor.submit(repo_to_neo4j_cpg, vuln_repo_prepatch, PROJECTS_NEO4J_DIR)
                    try:
                        result = future.result(timeout=TIMEOUT)
                    except concurrent.futures.TimeoutError:
                        print(f"[-] TimeoutError: Processing {cve_id} took longer than {TIMEOUT} seconds. Skipping...")
                        already_processed_cve.add(cve_id)
                        with open(already_processed_cve_path, 'w') as f:
                            json.dump(list(already_processed_cve), f)
                        continue
                    if result[0] is False:
                        print(f"[-] Skipping {cve_id} due to error in cpg generation for prepatch: {result[1]}")
                        already_processed_cve.add(cve_id)
                        with open(already_processed_cve_path, 'w') as f:
                            json.dump(list(already_processed_cve), f)
                        continue

                    print(f"    processing {vuln_repo_postpatch} ...")
                    future = executor.submit(repo_to_neo4j_cpg, vuln_repo_postpatch, PROJECTS_NEO4J_DIR)
                    try:
                        result = future.result(timeout=TIMEOUT)
                    except concurrent.futures.TimeoutError:
                        print(f"[-] TimeoutError: Processing {cve_id} took longer than {TIMEOUT} seconds. Skipping...")
                        already_processed_cve.add(cve_id)
                        with open(already_processed_cve_path, 'w') as f:
                            json.dump(list(already_processed_cve), f)
                        continue
                    if result[0] is False:
                        print(f"[-] Skipping {cve_id} due to error in cpg generation for postpatch: {result[1]}")
                        already_processed_cve.add(cve_id)
                        with open(already_processed_cve_path, 'w') as f:
                            json.dump(list(already_processed_cve), f)
                        continue
                    
                    print(f"[+] {cve_id} patch 前后的 cpg 及 neo4j 生成完成。")
                
                

                _map_key_1 = f"{cve_repo}-{commit_id}_prepatch"
                _map_key_2 = f"{cve_repo}-{commit_id}_postpatch"
                print("[ 1.5 ] 重置生成签名时 neo4j 数据库的接口 ...")
                change_conn_port(os.path.join(PROJECTS_NEO4J_DIR, _map_key_1, "conf/neo4j.conf"), "7689", "7475")
                change_conn_port(os.path.join(PROJECTS_NEO4J_DIR, _map_key_2, "conf/neo4j.conf"), "17689", "17475")

                change_neo4j_conf(_map_key_1, _map_key_2, neo4j_config_path)

                print("[ 2.  ] 进入根据 patch 寻找 source 和 sink 的阶段 ...")
                if not start_databases_with_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_1), _map_key_1) or not start_databases_with_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_2), _map_key_2):
                    print(f"[-] Skipping {cve_id} due to error in starting neo4j databases.")
                    already_processed_cve.add(cve_id)
                    with open(already_processed_cve_path, 'w') as f:
                        json.dump(list(already_processed_cve), f)
                    continue
                try:
                    potential_source_funcname_list, potential_sink_funcname_list = patch_analysis_with_cve(_map_key_1=_map_key_1,
                                                _map_key_2=_map_key_2,
                                                vuln_type=vuln_type,
                                                cve_id=cve_id,
                                                fixing_file=fixing_file,
                                                slice_results=intra_slice_results)

                    stop_databases_w_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_1), _map_key_1)
                    stop_databases_w_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_2), _map_key_2)
                    already_processed_cve.add(cve_id)
                    with open(already_processed_cve_path, 'w') as f:
                        json.dump(list(already_processed_cve), f)
                    
                    time.sleep(5)
                    if find_cve_in_hdd:
                        delete_neo4j_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_1))
                        delete_neo4j_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_2))
                    continue
                except Exception as e:
                    print(f"[-] Error processing {cve_id}: {e}")
                    print(traceback.format_exc())
                finally:
                    stop_databases_w_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_1), _map_key_1)
                    stop_databases_w_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_2), _map_key_2)

                banner_print(f"[+] {cve_id} source-patch-sink 定位与整合完成！")

                # 删除 neo4j 数据库以释放空间
                if find_cve_in_hdd:
                    delete_neo4j_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_1))
                    delete_neo4j_database(os.path.join(PROJECTS_NEO4J_DIR, _map_key_2))




def dataflow_get_and_sig_gene(cve_collection, cve_id_to_vuln_type):
    banner_print("CVE patch 分析完成。现在获取数据流并生成签名。")
    # 遍历已经生成的 neo4j ，根据 source sink 来获取数据流并生成签名
    potential_sink_funcname_dict_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "potential_sink_funcname_list.json")
    potential_source_funcname_dict_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "potential_source_funcname_list.json")

    with open(potential_sink_funcname_dict_path, 'r') as f:
        potential_sink_funcname_data = json.load(f)

    with open(potential_source_funcname_dict_path, 'r') as f:
        potential_source_funcname_data = json.load(f)


    cve_1201_stage3_file = "./cve_dataset/cve_data/php_dataset/cve_1201_stage3.json"
    cve_1201_collection = json.load(fp=open(cve_1201_stage3_file, 'r', encoding='utf-8'))
    for cve_id in os.listdir(sig_generate_slice_result_neo4j):
        try:
            banner_print(f"开始为 {cve_id} 生成签名 ...")
            signature_dir = os.path.join(sig_generate_dir, "signature_results", f"{cve_id}_sig_info")
            if os.path.exists(os.path.join(signature_dir, f"{cve_id}_prepatch_final_sink_context.json")):
                print(f"[+] {cve_id} signature already exists. skip ...")
                continue

            intra_slice_code_dir = os.path.join(sig_generate_slice_result, cve_id, "inter_to_intra")
            if cve_id in cve_1201_collection['sql_injection']:
                vuln_type = str(VULN_TYPE_STR_TO_DIGIT_DICT['sql_injection'])
                potential_sink_funcname_list = cve_1201_collection['sql_injection'][cve_id]['sink']['function_name']
                if type(potential_sink_funcname_list) is not list:
                    potential_sink_funcname_list = [potential_sink_funcname_list]
                potential_source_funcname_list = cve_1201_collection['sql_injection'][cve_id]['source']['function_name']
                if potential_source_funcname_list in {"_POST", "_GET", "_REQUEST", "_FILE", "_COOKIE"}:
                    potential_source_funcname_list = []
                else:
                    potential_source_funcname_list = [potential_source_funcname_list]
            elif cve_id in cve_id_to_vuln_type:
                commit_id = cve_collection[cve_id_to_vuln_type[cve_id]][cve_id]['fixing_commit']
                vuln_type = str(VULN_TYPE_STR_TO_DIGIT_DICT[cve_collection[cve_id_to_vuln_type[cve_id]][cve_id]['vuln_type']])
                existing_entry = next(
                    (e for e in potential_sink_funcname_data[vuln_type]
                    if str(e.get('commit_id')) == str(commit_id) and str(e.get('cve_id')) == str(cve_id)),
                    None
                )
                potential_sink_funcname_list = existing_entry.get('potential_sink_funcname_list', [])
                potential_source_funcname_list = potential_source_funcname_data.get(cve_id, [])

            cve_after_slice_neo4j_path = os.path.join(sig_generate_slice_result_neo4j, cve_id)

            change_conn_port(os.path.join(cve_after_slice_neo4j_path, "conf/neo4j.conf"), "7689", "7475")
            start_databases_with_database(cve_after_slice_neo4j_path, cve_id)

            if run_sig_source_sink(
                f"{cve_id}_prepatch",
                potential_source=potential_source_funcname_list,
                extend_vuln_model={int(vuln_type): potential_sink_funcname_list},
                cve_id=cve_id,
                task="sig"
            ):
                stop_databases_w_database(os.path.join(sig_generate_slice_result_neo4j, cve_id), cve_id)


        except:
            print(f"[-] Error generating signatures for {cve_id}: {traceback.format_exc()}")
        finally:
            pass



def generate_signatures_from_manually(cve_info_file, target_cve=None):
    process_count_perbatch = 50
    cve_collection = json.load(fp=open(cve_info_file, 'r', encoding='utf-8'))

    already_built_neo4j_path = "./sig_generate_record/build_neo4j_all.json"

    ensure_skip_cve_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "ensure_skip_cve.json")
    with open(ensure_skip_cve_path, 'r', encoding='utf-8') as fp:
        ensure_skip_cve = list(json.load(fp))

    already_processed_cve_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "already_processed_cve.json")
    with open(already_processed_cve_path, 'r') as f:
        already_processed_cve = set(json.load(f))

    cpg_generate_timeout_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "cpg_generate_timeout.json")
    with open(cpg_generate_timeout_path, 'r') as f:
        cpg_generate_timeout_cve = set(json.load(f))

    # 对于已经处理过的 并且保存到了 /mnt hdd data 中的不再处理
    with open(already_built_neo4j_path, 'r') as f:
        already_built_neo4j = set(json.load(f))


    TIMEOUT = 600
    cve_id_to_vuln_type = dict()
    target_cve_flag = False
    with concurrent.futures.ThreadPoolExecutor() as executor:
        print("======================================================")
        print("=====   patch analysis: 分析已知漏洞 patch 信息   =====")
        print("======================================================")
        for vuln_type, cve_data in cve_collection.items():
            vuln_type_str = vuln_type

            print(f"\nProcessing vulnerability type: {vuln_type_str}\n")
            for cve_id, cve_dict in tqdm(cve_data.items()):
                cve_id_to_vuln_type[cve_id] = vuln_type_str
                

                if target_cve is not None and cve_id != target_cve:
                    target_cve_flag = True
                    continue

                cve_repo = cve_dict['repo_name']
                vuln_type = VULN_TYPE_STR_TO_DIGIT_DICT[cve_dict['vuln_type']]

                source = cve_dict['source']
                sink = cve_dict['sink']

                print(f"\n\nProcessing CVE: {cve_id}, Repo: {cve_repo}")

                after_slice_neo4j_dir = os.path.join(sig_generate_slice_result_neo4j, cve_id)
                if os.path.exists(after_slice_neo4j_dir):
                    banner_print(f"[+] {cve_id} after slice neo4j already exists. skip ...")
                    continue

                if cve_id in already_processed_cve:
                    if not target_cve_flag:
                        banner_print(f"[+] {cve_id} already processed. skip ...")
                        continue

                if cve_id in ensure_skip_cve:
                    banner_print(f"[+] {cve_id} in ensure_skip_cve. skip ...")
                    continue

                if cve_id in cpg_generate_timeout_cve:
                    banner_print(f"[+] {cve_id} in cpg_generate_timeout_cve. skip ...")
                    continue

                
                intra_slice_results = os.path.join(sig_generate_slice_result, cve_id)  # 存放切片和LLM转义后的结果
                banner_print(f"正式开始处理 {cve_id}")
                
                _map_key_1 = f"{cve_repo}-{cve_id}_prepatch"
                _map_key_2 = f"{cve_repo}-{cve_id}_postpatch"
                print("[ 1.5 ] 重置生成签名时 neo4j 数据库的接口 ...")
                change_conn_port(os.path.join(PROJECTS_NEO4J_DIR, cve_id, "conf/neo4j.conf"), "7689", "7475")
                # change_conn_port(os.path.join(PROJECTS_NEO4J_DIR, cve_id, "conf/neo4j.conf"), "17689", "17475")

                change_neo4j_conf(_map_key_1, _map_key_2, neo4j_config_path)

                print("[ 2.  ] 进入根据手动指定 source 和 sink 寻找 source 和 sink 的阶段 ...")
                if not start_databases_with_database(os.path.join(PROJECTS_NEO4J_DIR, cve_id), _map_key_1):
                    print(f"[-] Skipping {cve_id} due to error in starting neo4j databases.")
                    already_processed_cve.add(cve_id)
                    with open(already_processed_cve_path, 'w') as f:
                        json.dump(list(already_processed_cve), f)
                    continue
                try:
                    potential_source_funcname_list, potential_sink_funcname_list = cve_analysis(_map_key_1=_map_key_1,
                            vuln_type=vuln_type,
                            cve_id=cve_id,
                            source_info=source,
                            sink_info=sink,
                            ss_depth=cve_dict.get('ss_depth'))
                    
                    stop_databases_w_database(os.path.join(PROJECTS_NEO4J_DIR, cve_id), _map_key_1)
                    already_processed_cve.add(cve_id)
                    with open(already_processed_cve_path, 'w') as f:
                        json.dump(list(already_processed_cve), f)
                    # time.sleep(5)
                except Exception as e:
                    print(f"[-] Error processing {cve_id}: {e}")
                    print(traceback.format_exc())
                finally:
                    stop_databases_w_database(os.path.join(PROJECTS_NEO4J_DIR, cve_id), _map_key_1)

    dataflow_get_and_sig_gene(cve_collection, cve_id_to_vuln_type)



if __name__ == '__main__':
    # subprocess.run(["zsh", "-i", "-c", "setjavaversion 7"])
    proxy = "http://192.168.115.81:10811"
    os.environ["http_proxy"] = proxy
    os.environ["https_proxy"] = proxy
    os.environ["all_proxy"] = proxy

    
    # 写个 argparer 来选择生成方式，第一种是通过 cve 信息生成，第二种是通过手动指定 cve 信息来生成， 一共解析两个参数：一个方法参数，一个 cve 信息文件的路径
    import argparse
    parser = argparse.ArgumentParser(description="Generate signatures for CVEs")
    parser.add_argument("--method", choices=["cve_info", "manual"], required=True, help="Method to generate signatures: from patch or manual")
    parser.add_argument("--cve_file", type=str, help="Path to the CVE information file.")
    parser.add_argument("--cve", type=str, help="指定处理的 CVE ID.")
    args = parser.parse_args()

    cve_info_patch_default_path = "./cve_dataset/cve_data/php_dataset/cve_1118_stage3.json"
    cve_info_manual_default_path = "./cve_dataset/cve_data/php_dataset/cve_1201_stage3.json"

    if args.method == "cve_info":
        if not args.cve_file:
            print("[-] 没有指定 cve info file，使用默认路径.")
            print(f"[+] 使用：{cve_info_patch_default_path}")
        # 调用通过 cve 信息生成签名的函数
        generate_signatures_from_patch(args.cve_file if args.cve_file else cve_info_patch_default_path, args.cve)
        print(f"Generating signatures from CVE info file: {args.cve_file}")
    elif args.method == "manual":
        # 调用通过手动指定 cve 信息生成签名的函数
        generate_signatures_from_manually(args.cve_file if args.cve_file else cve_info_manual_default_path, args.cve)
        print(f"Generating signatures manually from CVE info file: {args.cve_file}")
