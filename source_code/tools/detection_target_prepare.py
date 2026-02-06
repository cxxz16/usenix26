import os
import json
import subprocess
import traceback
import shutil
from tqdm import tqdm
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time
import openai
from core.chat import openai_chat

import configparser
from datetime import datetime
# from anthropic._tokenizer import tokenizer as claude_tokenizer
config = configparser.ConfigParser()
config.read("./core/config.ini")
base_url = config["database"]["api_base"]

# API Keys
API_KEYS = [
]

# Global lock for writing to shared files
file_lock = Lock()

PHP_REPOS_JSON = "./detection_projects_0120_papers"
STAR_RANGE = "_".join(os.path.basename(PHP_REPOS_JSON).split(".")[0].split("_")[2:]) 
print(f"Using STAR_RANGE: {STAR_RANGE}")
DETECTION_PROJECTS_DIR = f"./detection_projects_{STAR_RANGE}"
NEO4J_HOME = f"./detection_projects_neo4j_{STAR_RANGE}"
CPG_BASE_DIR = "./projects_cpg_multi"  # CPG
# Configuration
PHPJOERN_HOME = "./"

# Flags
EXTRACT_SINK_FLAG = True
GENE_CPG_FLAG = True

# Create CPG base directory if not exists
os.makedirs(NEO4J_HOME, exist_ok=True)
os.makedirs(CPG_BASE_DIR, exist_ok=True)
os.makedirs(DETECTION_PROJECTS_DIR, exist_ok=True)


def prepare_detection_proj(repo_name_with_suffix, repo_dir=None):
    if repo_dir is None:
        repo_dir = DETECTION_PROJECTS_DIR
    
    repo_name = repo_name_with_suffix.replace("-latest", "").lower()
    repo_path = os.path.join(repo_dir, repo_name)
    
    if os.path.exists(repo_path):
        print(f"[+] Project {repo_name} already exists at {repo_path}")
        return True, repo_path
    
    print(f"[+] Project {repo_name} not found, cloning...")

    if os.path.exists(os.path.join("./SanCheck/php-vuln-lab", repo_name)):
        print(f"[+] Found local copy of {repo_name}, copying...")
        shutil.move(os.path.join("./SanCheck/php-vuln-lab", repo_name), repo_path)
        return True, repo_path
    
    try:
        with open(PHP_REPOS_JSON, 'r', encoding='utf-8') as f:
            repos_dict = json.load(f)
        
        if repo_name not in repos_dict:
            print(f"[-] Cannot find repo url for {repo_name}. skip cloning...")
            return False, None
        
        repo_url = repos_dict[repo_name]

        current_dir = os.getcwd()
        os.chdir(repo_dir)
        
        is_clone_success = False
        for attempt in range(3):
            print(f"[+] Cloning {repo_name} (attempt {attempt + 1}/3)...")
            result = subprocess.run(
                ["git", "clone", repo_url],
                capture_output=True,
                text=True,
                timeout=300  
            )
            
            output = result.stdout + result.stderr
            print(output)
            
            if result.returncode == 0 and "fatal" not in output.lower():
                is_clone_success = True
                break
            
            time.sleep(2)  
        
        os.chdir(current_dir)
        
        if not is_clone_success:
            print(f"[-] Failed to clone {repo_name} after 3 attempts.")
            return False, None
        
        real_name = repo_url.split("/")[-1].replace(".git", "")
        cloned_path = os.path.join(repo_dir, real_name)
        
        if os.path.exists(cloned_path) and cloned_path != repo_path:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            os.rename(cloned_path, repo_path)
        
        if os.path.exists(repo_path):
            print(f"[+] Successfully cloned {repo_name} to {repo_path}")
            return True, repo_path
        else:
            print(f"[-] Clone succeeded but cannot find project at {repo_path}")
            return False, None
            
    except subprocess.TimeoutExpired:
        print(f"[-] Clone timeout for {repo_name}")
        os.chdir(current_dir)
        return False, None
    except Exception as e:
        print(f"[-] Error cloning {repo_name}: {e}")
        os.chdir(current_dir)
        return False, None


buchuli_process_repo = set()  


def llm_find_potential_sink(potential_sink_funcname: set, api_key: str, model: str) -> List[str]:
    from func_timeout import func_timeout, FunctionTimedOut
    
    try:
        return func_timeout(60, _inner_llm_find_potential_sink, 
                          args=(potential_sink_funcname, api_key, model))
    except FunctionTimedOut:
        print(f"Timeout with API key {api_key[:8]}... Returning empty.")
        return []


def _inner_llm_find_potential_sink(potential_sink_funcname: set, api_key: str, model: str, temp=0.1) -> List[str]:
    prompt = """
        ### Task:
        You are a senior PHP expert. Your task is to fully utilize your existing knowledge of PHP frameworks and third-party libraries, as well as the semantics of the given functions and methods, to carefully determine which ones directly perform database operations or wrapper interfaces that perform database operations. This includes native interfaces, third-party library interfaces, and wrapper functions/methods for database interfaces. Please follow the steps below, think through them sequentially, and return only the function call APIs that satisfy all the conditions.

        ### Think step by step:
        Step 1: First, identify the following categories of function calls:
        a. PHP built-in database interfaces
        e.g., mysqli_query, mysqli_connect, PDO::query, etc.

        b. Third-party library database interfaces
        e.g., $conn->executeQuery, DB::select(), etc.

        c. Encapsulated functions/methods for database operations
        e.g., $db->query(), query(), rows(), which may internally call SQL operations.

        Step 2: From the identified function calls, Exclude and do not return any API or function call if it matches any of the following:
        1. If the API involves ORM entity-level operations(e.g., $user->save(); User::find(1); User::where('email', $email)->exists(); DB::table("item_tag")->insertGetId() etc.) then exclude it.
        2. If the API uses any form of query-builder–style SQL construction (e.g., $query = DB::table('users')->where('id', 1)->get();) then exclude it.
        3. If the API is not related to database behavior (arrays, collections, caches, etc.) then exclude it.
        4. If the database-related behavior of the API cannot be determined with sufficient confidence, then exclude it — do not guess or infer beyond clear evidence.
        5. If the API has any semantics for database configuration operations such as connect close, excluding them, we are concerned about operations such as queries.
        6. Pay attention to any function calls that contain the word "query".
        7. Carefully review each callsite one by one.

        ### Input
        {call_expr}

        ### Output Requirements
        Please output a list of the methods/functions that meet the criteria, wrapped in an XML tag `<answer>`. Keep your thoughts in mind, but don't show them in the output.

        ### Output 
        <answer>[ ]</answer>
    """

    prompt = prompt.format(call_expr=potential_sink_funcname)

    client = openai.OpenAI(api_key=api_key, base_url=base_url)
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
        temperature=temp,
    )
    response = response.choices[0].message.content




    print("LLM Response:", response)
    answer = []
    # Extract the answer from the response
    if "<answer>" in response and "</answer>" in response:
        answer = response.split("<answer>")[1].split("</answer>")[0].strip()
        print("Extracted Answer:", answer)

    #  answer  list
    custom_sink_funcname_list = set()
    if answer.startswith("[") and answer.endswith("]"):
        items = answer[1:-1].split(",")
        for item in items:
            item = item.strip().strip("'").strip('"')
            if item:
                custom_sink_funcname_list.add(item)

    return list(custom_sink_funcname_list)


def repo_to_neo4j_cpg(repo_dir, repo_name, cpg_project_dir, neo4j_home=None):
    os.environ["HEAP"] = "3G"
    
    neo4j_home = neo4j_home if neo4j_home is not None else NEO4J_HOME
    
    # Neo4j
    if os.path.exists(os.path.join(neo4j_home, repo_name)):
        print(f"[+] cpg & neo4j for {repo_name} already exists. skip cpg generation.")
        return True, None
    
    nodes_path = os.path.join(cpg_project_dir, "nodes.csv")
    rels_path = os.path.join(cpg_project_dir, "rels.csv")
    
    def run_php2ast(file_path, output_nodes, output_rels):
        print(f'[{repo_name}] php2ast is running...')
        result = subprocess.run(
            ["php", "./php2ast/src/Parser.php", 
             "-n", output_nodes,
             "-r", output_rels,
             file_path], 
            cwd=PHPJOERN_HOME
        )
        if result.returncode != 0:
            print(f"[{repo_name}] php2ast failed with return code: {result.returncode}")
            return False
        
        if not os.path.exists(output_nodes) or not os.path.exists(output_rels):
            print(f"[{repo_name}] nodes.csv or rels.csv not found")
            return False
        
        return True
    
    def run_phpast2cpg(nodes_file, rels_file, output_dir):
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
        print(f'[{repo_name}] neo4j database generating...')
        
        if db_filename.endswith("postpatch"):
            bolt_port = "17687"
            http_port = "17474"
        else:
            bolt_port = "7687"
            http_port = "7474"
        
        result = subprocess.run(
            ["sudo", "bash", 
             os.path.join(PHPJOERN_HOME, "neo4j-admin-import_vari.sh"),
             db_filename, bolt_port, http_port, neo4j_home],
            cwd=cpg_dir
        )
        
        if result.returncode != 0:
            print(f"[{repo_name}] admin import failed with return code: {result.returncode}")
            return False
        
        subprocess.run(
            ["sudo", "chown", "-R", ":", db_filename], 
            cwd=neo4j_home
        )
        return True
    
    def cleanup_cpg_dir():
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
        
        print(f"[{repo_name}] ✅")
        return True, None
        
    except Exception as e:
        print(f"[{repo_name}] Error: {traceback.format_exc()}")
        cleanup_cpg_dir()
        return False, str(e)

ERROR_PROJECTS_PATH = f"./detection_potential_sink_from_clusting_and_llm/error_projects_{STAR_RANGE}.json"

if not os.path.exists(ERROR_PROJECTS_PATH):
    with open(ERROR_PROJECTS_PATH, "w") as f:
        json.dump({}, f)



def load_error_projects():
    with file_lock:
        if os.path.exists(ERROR_PROJECTS_PATH):
            with open(ERROR_PROJECTS_PATH, "r") as f:
                return json.load(f)
        return {}


def save_error_project(project_name, error_stage, error_msg):
    with file_lock:
        error_projects = load_error_projects()
        
        if project_name not in error_projects:
            error_projects[project_name] = {
                "error_stage": error_stage,
                "error_message": error_msg,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attempts": 1
            }
        else:
            error_projects[project_name]["error_stage"] = error_stage
            error_projects[project_name]["error_message"] = error_msg
            error_projects[project_name]["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            error_projects[project_name]["attempts"] += 1
        
        with open(ERROR_PROJECTS_PATH, "w") as f:
            json.dump(error_projects, f, indent=4)


def is_error_project(project_name):
    error_projects = load_error_projects()
    return project_name in error_projects


# TARGET_REPO_TARGET = "webim"
def process_single_project(args):
    idx, target, api_key, repo_sink_dict_path = args
    
    target = target.lower()
    target_repo = target

    print(f"[Thread-{idx}] Target repo: {target_repo}")

    # if target_repo != TARGET_REPO_TARGET:
    #     return None
    
    print(f"\n[Thread-{idx}] Processing {target} with API key {api_key[:8]}...")
    
    # CPG
    cpg_project_dir = os.path.join(CPG_BASE_DIR, target_repo)
    os.makedirs(cpg_project_dir, exist_ok=True)
    
    try:
        # 
        if target_repo in buchuli_process_repo:
            print(f"[Thread-{idx}] {target_repo} . skip ...")
            return None
        
        success, target_repo_path = prepare_detection_proj(
            f"{target_repo}-latest", 
            repo_dir=DETECTION_PROJECTS_DIR
        )

        # return None
        if not success:
            print(f"[Thread-{idx}] prepare_detection_proj failed for {target}. skip ...")
            return None
        

        
        # Load current repo_sink_dict
        with file_lock:
            if os.path.exists(repo_sink_dict_path):
                with open(repo_sink_dict_path, "r") as f:
                    repo_sink_dict = json.load(f)
            else:
                repo_sink_dict = {}

        neo4j_path = os.path.join(NEO4J_HOME, f"{target_repo}_prepatch")
        if os.path.exists(neo4j_path):
            print(f"[Thread-{idx}] {target_repo}_prepatch neo4j already exists. skip ...")
            return target_repo
        
        from code_preprocess import preprocess_API
        preprocess_API(
            target_repo_path,
            in_place=True
        )
        
        # Extract potential sinks if needed
        if EXTRACT_SINK_FLAG and (target_repo not in repo_sink_dict):    # or repo_sink_dict[target_repo] == []
            print(f"[Thread-{idx}] Extracting potential sinks for {target_repo}...")
            
            ss_dir = "./workflow/source_sink_identify"
            
            result = subprocess.run(
                ["python", "ss_extend.py", target, DETECTION_PROJECTS_DIR], 
                cwd=ss_dir
            )
            if result.returncode != 0:
                print(f"[Thread-{idx}] ss_extend.py failed.")
                return None
            
            result = subprocess.run(
                ["python", "clustering.py", target], 
                cwd=ss_dir
            )
            if result.returncode != 0:
                print(f"[Thread-{idx}] clustering.py failed.")
                return None
            
            potential_sinks_dir = os.path.join(ss_dir, "potential_sink_funcname")
            sink_file = os.path.join(potential_sinks_dir, f"{target}_potential_sink_funcs.txt")
            
            if not os.path.exists(sink_file):
                print(f"[Thread-{idx}] {target}_potential_sink_funcs.txt not found. skip ...")
                return None
            
            with open(sink_file, "r") as f:
                funcs = set(f.read().splitlines())
            
            print(f"[Thread-{idx}] Total candidate sink functions for {target}: {len(funcs)}")
            print(f"[Thread-{idx}] Calling LLM to identify potential sinks...")
            potential_sinks = llm_find_potential_sink(funcs, api_key, model="gpt-5-2025-08-07")
            print(f"[Thread-{idx}] Total potential sinks for {target}: {len(potential_sinks)}")
            
            # Update repo_sink_dict with lock
            with file_lock:
                with open(repo_sink_dict_path, "r") as f:
                    repo_sink_dict = json.load(f) if os.path.exists(repo_sink_dict_path) else {}
                
                repo_sink_dict[target_repo] = potential_sinks
                
                with open(repo_sink_dict_path, "w") as f:
                    json.dump(repo_sink_dict, f, indent=4)
        
        print(f"[Thread-{idx}] Finished extracting potential sinks for {target_repo}.")
        
        # Generate CPG and import to Neo4j
        if GENE_CPG_FLAG:
            if os.path.exists(os.path.join(NEO4J_HOME, f"{target_repo}_prepatch")):
                print(f"[Thread-{idx}] {target_repo}_prepatch neo4j already exists. skip ...")
                return target_repo
            
            print(f"[Thread-{idx}] cpg and neo4j ...")
            
            success, error = repo_to_neo4j_cpg(
                target_repo_path, 
                f"{target_repo}_prepatch",
                cpg_project_dir,
                NEO4J_HOME
            )
            
            if not success:
                print(f"[Thread-{idx}] Failed at stage: {error}")
                return None
        
        return target_repo
        
    except Exception as e:
        print(f"[Thread-{idx}] Exception: {traceback.format_exc()}")
        return None


def main(num_workers):
    model = "gpt-5"
    
    # Load configurations
    repo_sink_dict_path = "./potential_sinks_detection/repo_sink_dict_gpt-5.json"
    if not os.path.exists(repo_sink_dict_path):
        with open(repo_sink_dict_path, "w") as f:
            json.dump({}, f)

    # with open(PHP_REPOS_JSON, "r") as f:
    #     php_projects_dict = json.load(f)
    
    # projects = list(php_projects_dict.keys())[100:200]
    projects = os.listdir(DETECTION_PROJECTS_DIR)

    pass_projects = ["civicrm-core", "tuleap", "opensource-casino-v10", "attack-defense-challenges"]
    
    tasks = [
        (idx, project, API_KEYS[idx % len(API_KEYS)], repo_sink_dict_path)
        for idx, project in enumerate(projects) if project not in pass_projects
    ]
    
    max_workers = min(len(API_KEYS), num_workers)
    
    print(f"Starting processing with {max_workers} worker threads...")
    
    completed_projects = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_project = {
            executor.submit(process_single_project, task): task[1] 
            for task in tasks
        }
        
        # tqdm
        with tqdm(total=len(tasks)) as pbar:
            for future in as_completed(future_to_project):
                project = future_to_project[future]
                try:
                    result = future.result()
                    if result:
                        completed_projects.append(result)
                        print(f"\n Successfully completed: {result}")
                except Exception as e:
                    print(f"\n Error processing {project}: {e}")
                finally:
                    pbar.update(1)
    
    print(f"\n{'='*60}")
    print(f"Processing complete!")
    print(f"Successfully processed: {len(completed_projects)}/{len(tasks)} projects")
    print(f"{'='*60}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Prepare detection targets.")
    parser.add_argument("--numworks", type=int, default=1, help="Number of worker threads.")
    args = parser.parse_args()
    main(args.numworks)