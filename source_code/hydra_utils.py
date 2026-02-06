import os
import subprocess
import time
import json
import shutil
from typing import List
from icecream import ic
ic.configureOutput(includeContext=True)


def repo_to_neo4j_cpg(repo_dir, neo4j_home=None):
    os.environ["HEAP"] = "3G"
    PHPJOERN_HOME = ""
    NEO4J_HOME = neo4j_home if neo4j_home is not None else "detection_inter_slice_result_neo4j"
    PROJECTS_CPG_DIR = "projects_cpg"

    #  cpg 
    if repo_dir.endswith("inter_to_intra"):
        repo_name = os.path.basename(repo_dir.replace("/inter_to_intra", ""))
    else:
        repo_name = os.path.basename(repo_dir)

    if os.path.exists(os.path.join(NEO4J_HOME, f"{repo_name}")):
        print(f"[+] cpg & neo4j for {repo_name} already exists. skip cpg generation.")
        return True, None
    # 
    # else:
    #     logger.info(f"[!]  neo4j cpg   {repo_dir}")
    #     return False, None

    def run_php2ast(file_path):
        tip = 'php2ast is running...'
        ic(tip)
        result = subprocess.run(["php", "./php2ast/src/Parser.php", file_path], cwd=PHPJOERN_HOME)
        if result.returncode != 0:
            tip = "php2ast failed with return code:"
            ic(tip, result.returncode)
            return False
        nodes_path = os.path.join(PHPJOERN_HOME, "nodes.csv")
        rels_path = os.path.join(PHPJOERN_HOME, "rels.csv")
        if not os.path.exists(nodes_path) or not os.path.exists(rels_path):
            return False
        
        # tip = 'mv nodes and rels to ' + target_dir
        # ic(tip)
        # subprocess.run(["mv", "nodes.csv", os.path.join(target_dir, "nodes.csv")], cwd=PHPJOERN_HOME)
        # subprocess.run(["mv", "rels.csv", os.path.join(target_dir, "rels.csv")], cwd=PHPJOERN_HOME)
        return True

    def run_phpast2cpg():
        tip = 'phpast2cpg is running...'
        ic(tip)
        result = subprocess.run(["java", "-jar", "./phpast2cpg.jar", "-n", "./nodes.csv", "-e", "./rels.csv"], cwd=PHPJOERN_HOME)
        
        if result.returncode != 0:
            tip = "phpast2cpg failed with return code:"
            ic(tip, result.returncode)
            return False
        return True

    def run_java_import(db_filename):
        subprocess.run(["zsh", "-i", "-c", "setjavaversion 11"])
        tip = 'neo4j database generating...'
        ic(tip)
        # cmd = f"sudo bash ./neo4j-admin-import.sh {db_filename}"
        if db_filename.endswith("postpatch"):
            result = subprocess.run(["sudo", "bash", "./neo4j-admin-import_vari.sh", db_filename, "17687", "17474", NEO4J_HOME], cwd=PHPJOERN_HOME)
        else:
            result = subprocess.run(["sudo", "bash", "./neo4j-admin-import_vari.sh", db_filename, "7687", "7474", NEO4J_HOME], cwd=PHPJOERN_HOME)
        if result.returncode != 0:
            tip = "admin import failed with return code:"
            ic(tip, result.returncode)
            return False

        subprocess.run(["sudo", "chown", "-R", ":", db_filename], cwd=NEO4J_HOME)
        return True

    def cleanup_cpg_dir():
        # if os.path.exists(cpg_dir):
        #     tip = f"cleaning up {cpg_dir} due to failure"
        #     ic(tip)
        #     shutil.rmtree(cpg_dir, ignore_errors=True)
        pass

    if not run_php2ast(repo_dir):
        cleanup_cpg_dir()
        return False, "php2ast_pre"

    if not run_phpast2cpg():
        cleanup_cpg_dir()
        return False, "phpast2cpg_pre"

    if not run_java_import(repo_name):
        cleanup_cpg_dir()
        return False, "batch_import_pre"

    print("✅ ")
    return True, None



def banner_print(str):
    print("---------------------------------------------")
    print(str)
    print("---------------------------------------------")



def start_databases_with_database(neo4j_database, connector_name):
    print(f"Starting {connector_name} databases ...")
    db = f"{neo4j_database}"

    result = subprocess.run(
        ["sudo", f"{neo4j_database}/bin/neo4j", "status"],
        capture_output=True,
        text=True,
        check=False
    )
    if result.returncode != 0:
        print(f"{connector_name} is not running.")
    else:
        output = result.stdout.strip().lower()
        if "is running at" in output:
            print(f"{connector_name} is already running.")
            return True

    if not os.path.exists(db):
        print(f"[!] Database path {db} does not exist.")
        return
    # if check_null_graphdb(os.path.join(db, "data/graph.db/neostore.nodestore.db")):
    #     return False
    # if connector_name.endswith("postpatch"):
    #     conf_file = os.path.join(db, "conf/neo4j-server.properties")
    #     change_https_port(conf_file)
    
    io = os.popen(f"sudo {neo4j_database}/bin/neo4j start").read()
    time.sleep(8)
    io = os.popen(
        # f"tail -n 10 {DATABASE_PATH}/{connector_name}/data/log/console.log"
        f"tail -n 10 {neo4j_database}/logs/neo4j.log"
    ).read()
    print(io, flush=True)

    print("Waiting for 30s to make sure neo4j opened...")
    for i in range(0, 3):
        time.sleep(4)

    return True

def check_null_graphdb(filepath):
    #  graph db 
    print(os.path.getsize(filepath))
    if os.path.exists(filepath) and os.path.getsize(filepath) == 16:
        return True
    return False


def change_neo4j_conf(key1, key2, NEO4J_CONFIGURE_MAP_PATH):
    f = open(NEO4J_CONFIGURE_MAP_PATH, "r")
    json_data = json.load(f)
    new_data = {}
    for key, data in json_data.items():
        if key.endswith("_prepatch"):
            new_data[key1] = data
        if key.endswith("_postpatch"):
            new_data[key2] = data
    f.close()
    f = open(NEO4J_CONFIGURE_MAP_PATH, "w")
    json.dump(new_data, f, indent=4)
    f.close()


def change_conn_port(filepath, new_bolt_port, new_http_port):
    with open(filepath, 'r') as file:
        lines = file.readlines()
    with open(filepath, 'w') as file:
        for line in lines:
            if "dbms.connector.bolt.listen_address=:" in line:
                file.write(f"dbms.connector.bolt.listen_address=:{new_bolt_port}\n")
            elif "dbms.connector.http.listen_address=:" in line:
                file.write(f"dbms.connector.http.listen_address=:{new_http_port}\n")
            else:
                file.write(line)
    file.close()


def stop_databases_w_database(database_path, connector_name):
    #  database
    print(f"Stopping {connector_name} databases ...")
    result = subprocess.run(
        ["sudo", f"{database_path}/bin/neo4j", "status"],
        capture_output=True,
        text=True,
        check=False
    )
    if result.returncode != 0:
        print(f"{connector_name} is not running.")
    else:
        output = result.stdout.strip().lower()
        if "is running at" in output:
            print(f"\n\n{connector_name} is running... ")
            print(f"Stopping database: {connector_name}...\n")
            io = os.popen(f"sudo {database_path}/bin/neo4j stop").read()
            for i in range(0, 2):
                time.sleep(4)
        else:
            print(f"{connector_name} is not running.")


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
            elif "caller_name" in node:
                if node["caller_name"] in potential_funcname_list:
                    filtered_paths.append(path)
                    break
            
    all_paths.clear()
    all_paths.extend(filtered_paths)


def filter_source_sink_paths(all_paths, potential_funcname_list: List[str]):
    filtered_paths = []
    for path in all_paths:
        for node in path:
            if "marker" in node:
                if node["marker"] == "SOURCE":
                    filtered_paths.append(path)
                    break
            elif "callee_name" in node:
                if node["call_site_code"] in potential_funcname_list:
                    filtered_paths.append(path)
                    break
            elif "caller_name" in node:
                if node["call_site_code"] in potential_funcname_list:
                    filtered_paths.append(path)
                    break
            
    all_paths.clear()
    all_paths.extend(filtered_paths)



def merge_call_path(call_paths: list[list[dict]]):
    return call_paths



def ss_in_inter(call_path):
    init_funcid = -1
    if call_path:
        init_funcid = call_path[0]['funcid']
    for node in call_path:
        if node['funcid'] != init_funcid:
            return True
    return False

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



def search_cve_in_hdd_data_cache(repo_name, commit_hash):
    hdd_data_dir = "/mnt/hdd_data/projects_neo4j"
    hdd_srccode_dir = "/mnt/hdd_data/projects"
    processed_dir = "projects_neo4j"
    processed_srccode_dir = "projects"

    target = f"{repo_name}-{commit_hash}"
    target_finded = False
    for project_dir in os.listdir(hdd_data_dir):
        if project_dir.startswith(target):
            target_prepatch_path = os.path.join(hdd_data_dir, f"{target}_prepatch")
            target_postpatch_path = os.path.join(hdd_data_dir, f"{target}_postpatch")
            if os.path.exists(target_prepatch_path) and os.path.exists(target_postpatch_path):
                print(f"[+] Found cached project {project_dir} in hdd data cache.")
                target_finded = True
                break

    if target_finded:
        #  neo4j  processed_dir 
        dest_prepatch_path = os.path.join(processed_dir, f"{repo_name}-{commit_hash}_prepatch")
        dest_postpatch_path = os.path.join(processed_dir, f"{repo_name}-{commit_hash}_postpatch")
        if not os.path.exists(dest_prepatch_path):
            shutil.copytree(target_prepatch_path, dest_prepatch_path)
        if not os.path.exists(dest_postpatch_path):
            shutil.copytree(target_postpatch_path, dest_postpatch_path)

        print(f"[+] Copied cached neo4j projects to {processed_dir}.")

        # 
        dest_prepatch_srccode_path = os.path.join(processed_srccode_dir, f"{repo_name}-{commit_hash}_prepatch")
        dest_postpatch_srccode_path = os.path.join(processed_srccode_dir, f"{repo_name}-{commit_hash}_postpatch")
        source_prepatch_srccode_path = os.path.join(hdd_srccode_dir, f"{repo_name}-{commit_hash}_prepatch")
        source_postpatch_srccode_path = os.path.join(hdd_srccode_dir, f"{repo_name}-{commit_hash}_postpatch")
        if not os.path.exists(dest_prepatch_srccode_path):
            shutil.copytree(source_prepatch_srccode_path, dest_prepatch_srccode_path)
        if not os.path.exists(dest_postpatch_srccode_path):
            shutil.copytree(source_postpatch_srccode_path, dest_postpatch_srccode_path)

        return True
    else:
        print(f"[-] No cached project found for {target} in hdd data cache.")
        return False
    

def delete_neo4j_database(db_path):
    if os.path.exists(db_path):
        print(f"[+] Deleting neo4j database at {db_path} to free up space.")
        shutil.rmtree(db_path, ignore_errors=True)


def add_line_numbers(code: str, skip_line: int = None) -> str:
    """
    
     1  4 
    """
    lines = code.splitlines()
    # 
    skip_lines = []
    if skip_line is not None and 1 <= skip_line <= len(lines):
        skip_lines = lines[:skip_line]
        lines = lines[skip_line:]

    numbered_lines = [f"{i + 1:<4} {line}" for i, line in enumerate(lines)]
    return "\n".join(skip_lines + numbered_lines)



import re
import sys
import json
from pathlib import Path
from collections import defaultdict

FILE_RE  = re.compile(r'^\s*//\s*File:\s*(.+?)\s*$')
SCOPE_RE = re.compile(r'^\s*//\s*Scope:\s*(.+?)\s*$')
FUNC_RE  = re.compile(
    r'^\s*(?:abstract\s+|final\s+)?'
    r'(?:public|protected|private)?\s*'
    r'(?:static\s+)?'
    r'function\s+&?\s*([A-Za-z_]\w*)\s*\(',
    re.MULTILINE
)

def extract_from_text(text: str):
    """
    “ // File: ...”
     File  Scope function 
    """
    result = defaultdict(set)

    current_file = None
    current_scope = None
    buf = []

    def flush():
        nonlocal current_file, current_scope, buf
        if not current_file:
            buf = []
            current_scope = None
            return

        block = "\n".join(buf)

        #  Global Scope Global Scope
        if current_scope and current_scope.strip().lower() == "global scope":
            result[current_file].add("Global Scope")
       
        for name in FUNC_RE.findall(block):
                result[current_file].add(name)

        buf = []
        current_scope = None

    for line in text.splitlines():
        mfile = FILE_RE.match(line)
        if mfile:
            flush()
            current_file = mfile.group(1).strip()
            continue

        mscope = SCOPE_RE.match(line)
        if mscope:
            current_scope = mscope.group(1).strip()
            # Scope  buf 
            buf.append(line)
            continue

        if current_file:
            buf.append(line)

    flush()
    return result


def extract_file_function(files: List[Path]):
    merged = defaultdict(set)

    for p in files:
        text = Path(p).read_text(encoding="utf-8", errors="ignore")
        partial = extract_from_text(text)
        for f, names in partial.items():
            merged[f].update(names)

    # path: [..]
    #  + JSON
    human = []
    for f in sorted(merged.keys()):
        names = sorted(merged[f])
        human.append(f"{f}: [{', '.join(names)}]")
    print("\n".join(human))

    return merged

    #  JSON
    # print(json.dumps({f: sorted(v) for f, v in merged.items()}, ensure_ascii=False, indent=2))



CVE_DATABASE_ROOT = Path("./cve-database/cvelistV5/cves")


from typing import Optional
def get_cve_description(cve_id: str) -> Optional[str]:
    """Return the best available description for the provided CVE identifier.

    The function looks up the matching CVE JSON entry inside the CVE v5
    repository located at ``CVE_DATABASE_ROOT`` and returns the English
    description when available. If the file or description cannot be found,
    ``None`` is returned.
    """

    if not cve_id:
        raise ValueError("cve_id must be a non-empty string")

    normalized_id = cve_id.strip().upper()
    if not normalized_id.startswith("CVE-"):
        raise ValueError("cve_id must follow the CVE-YYYY-NNNN format")

    parts = normalized_id.split("-")
    if len(parts) != 3:
        raise ValueError("cve_id must contain three dash-separated segments")

    year, sequence = parts[1], parts[2]
    if not (year.isdigit() and sequence.isdigit()):
        raise ValueError("year and sequence portions of cve_id must be numeric")

    sequence_number = int(sequence)
    range_directory = f"{sequence_number // 1000}xxx"
    cve_file = CVE_DATABASE_ROOT / year / range_directory / f"{normalized_id}.json"

    if not cve_file.is_file():
        raise FileNotFoundError(f"CVE entry not found: {cve_file}")

    with cve_file.open("r", encoding="utf-8") as cve_fp:
        cve_data = json.load(cve_fp)

    cna_container = cve_data.get("containers", {}).get("cna", {})
    descriptions = cna_container.get("descriptions", []) or []

    for entry in descriptions:
        if entry.get("lang", "").lower() == "en" and entry.get("value"):
            return entry["value"]

    for entry in descriptions:
        if entry.get("value"):
            return entry["value"]

    return None


def parse_vuln_answer(output: str) -> bool:
    """
    Parse model output like:
      <ANSWER>VULNERABLE</ANSWER>
    or
      <ANSWER>NO</ANSWER>

    Return True if VULNERABLE, else False.
    """
    if not isinstance(output, str):
        return False

    m = re.search(r"<ANSWER>\s*(VULNERABLE|NO)\s*</ANSWER>", output, flags=re.IGNORECASE)
    if not m:
        return False

    verdict = m.group(1).strip().upper()
    return verdict == "VULNERABLE"