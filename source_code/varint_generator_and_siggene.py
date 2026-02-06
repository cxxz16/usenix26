import subprocess
import os
import json 
from collections import OrderedDict
import re
from hydra_utils import *
from signature_generator import run_sig_source_sink, VULN_TYPE_STR_TO_DIGIT_DICT
from tqdm import tqdm
from variant_agent import mutate_complete, variant_vuln_patch_complete, vuln_check
from concurrent.futures import ThreadPoolExecutor, as_completed


CVE_CODE_DIR = "./intra_slice_result"
VARIANT_AGENT_DIR = "./multi_agent/workflow"
PATCH_ANALYSIS_CACHE_DIR = "./hydra/intermediate_results/sig_from_patch"
CVE_RC_CODE_DIR = "./hydra/sig_gene_results/slice_results"
CVE_COLLECTION_FILE = "./cve_dataset/cve_data/php_dataset/cve_1118_stage3.json"
VARIANT_CODE_RESULTS_DIR = "./hydra/sig_gene_results/variant_results"
VARIANT_CODE_RESULTS_NEO4J_DIR = "./hydra/sig_gene_results/variant_results_neo4j"
VARIANT_NEO4J_CONFIG = "./hydra/config/neo4j_varsig_gene.json"

variant_sig_generate_slice_result_neo4j = "./hydra/sig_gene_results/variant_results_neo4j"
sig_generate_dir = "./hydra/sig_gene_results"

os.makedirs(VARIANT_CODE_RESULTS_NEO4J_DIR, exist_ok=True)
def _normalize_df_path_str(p: str) -> str:
    if not p:
        return ""
    s = p.strip()

    s = re.sub(r"^\[Path\s*\d+\]\s*", "", s)

    s = re.sub(r"\s*->\s*", " -> ", s)

    s = re.sub(r"\s+", " ", s).strip()
    return s


def clean_dataflow_path(cve_id):

    cve_sig_info_path = os.path.join(signature_results_sig_info, f"{cve_id}_sig_info")
    if not os.path.isdir(cve_sig_info_path):
        return False

    dataflow_str_list_file = os.path.join(
        cve_sig_info_path, f"{cve_id}_prepatch_final_dataflow_str_list.json"
    )
    if not os.path.exists(dataflow_str_list_file):
        return False

    with open(dataflow_str_list_file, "r", encoding="utf-8") as f:
        dataflow_str_list = json.load(f)

    file_dfpath_odict = {}  # file_path -> OrderedDict(clean_path -> None)

    file_dfpath_list = dataflow_str_list.get("inter", [])
    for file_dfpath_item in file_dfpath_list:
        if not isinstance(file_dfpath_item, dict):
            continue

        for file_path_key, df_path_list in file_dfpath_item.items():
            if file_path_key not in file_dfpath_odict:
                file_dfpath_odict[file_path_key] = OrderedDict()

            if not isinstance(df_path_list, list):
                df_path_list = [df_path_list]

            for raw_path in df_path_list:
                clean_path = _normalize_df_path_str(raw_path)
                if clean_path:
                    file_dfpath_odict[file_path_key][clean_path] = None
    file_dfpath_dict = {}
    for fp, od in file_dfpath_odict.items():
        numbered = []
        for idx, clean_path in enumerate(od.keys(), start=1):
            numbered.append(f"[Path {idx}] {clean_path}\n")
        file_dfpath_dict[fp] = numbered

    out_file = os.path.join(
        cve_sig_info_path, f"{cve_id}_prepatch_final_file2paths_inter.json"
    )
    with open(out_file, "w", encoding="utf-8") as wf:
        json.dump(file_dfpath_dict, wf, ensure_ascii=False, indent=2)

    total_paths = sum(len(v) for v in file_dfpath_dict.values())
    print(f"[+] {cve_id} done: {len(file_dfpath_dict)} files, {total_paths} unique paths -> {out_file}")

    return out_file


MAX_CVE_WORKERS = 4  
MODEL = ""
CLAUDE_API_KEY = ""

def process_one_cve(cve_sig_info):
    if not cve_sig_info.endswith("_sig_info"):
        return ("skip", None, None)

    cve_id = cve_sig_info.replace("_sig_info", "")
    variant_code_cve = os.path.join(VARIANT_CODE_RESULTS_DIR, "variant_code", cve_id)
    cve_id_sink_funcname = cve_id_sink_source_dict.get(cve_id, {}).get("sink", [])
    cve_id_sink_funcname = ",".join(cve_id_sink_funcname)

    # skip 逻辑保持不变
    if os.path.exists(variant_code_cve) and len(os.listdir(variant_code_cve)) >= 3:
        print(f"[+] {variant_code_cve} already exists. skip variant generation ...")
        return ("skip", cve_id, variant_code_cve)

    banner_print(f"[+] Processing {cve_id} ...")
    print("[+] Cleaning dataflow paths ...")
    out_file = clean_dataflow_path(cve_id)

    with open(out_file, "r", encoding="utf-8") as f:
        file2paths = json.load(f)

    vuln_exists = []
    for src_file in file2paths.keys():
        result = vuln_check(cve_id, src_file)
        if result:
            vuln_exists.append(src_file)
        else:
            print(f"[-] {src_file} does not contain the vulnerability. skip ...")

    for src_file, dataflow_paths in file2paths.items():
        if src_file in vuln_exists:
            mutate_complete(cve_id, src_file, dataflow_paths, cve_id_sink_funcname, model=MODEL, api_key=CLAUDE_API_KEY)

    print(f"[+] {cve_id} Variant generation completed.")
    return ("ok", cve_id, variant_code_cve)



cve_id_sink_source_dict = dict()

def main():
    cve_list = list(os.listdir(signature_results_sig_info))
    ok_jobs = []

    cve_collection = json.load(fp=open(CVE_COLLECTION_FILE, 'r', encoding='utf-8'))
    cve_id_to_vuln_type = dict()
    cve_1201_stage3_file = "./cve_dataset/cve_data/php_dataset/cve_1201_stage3.json"
    cve_1201_collection = json.load(fp=open(cve_1201_stage3_file, 'r', encoding='utf-8'))
    for vuln_type, cve_data in cve_collection.items():
        vuln_type_str = vuln_type
        print(f"\nProcessing vulnerability type: {vuln_type_str}\n")

        for cve_id, cve_dict in tqdm(cve_data.items()):

            if cve_id not in cve_id_to_vuln_type:
                cve_id_to_vuln_type[cve_id] = vuln_type_str

            cve_repo = cve_dict['repo_name']
            vuln_type = VULN_TYPE_STR_TO_DIGIT_DICT[cve_dict['vuln_type']]

    potential_sink_funcname_dict_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "potential_sink_funcname_list.json")
    potential_source_funcname_dict_path = os.path.join(PATCH_ANALYSIS_CACHE_DIR, "potential_source_funcname_list.json")

    with open(potential_sink_funcname_dict_path, 'r') as f:
        potential_sink_funcname_data = json.load(f)

    with open(potential_source_funcname_dict_path, 'r') as f:
        potential_source_funcname_data = json.load(f)


    for cve_id in tqdm(os.listdir(os.path.join(VARIANT_CODE_RESULTS_DIR, "variant_code", MODEL))):
        variant_code_cve = os.path.join(VARIANT_CODE_RESULTS_DIR, "variant_code", MODEL, cve_id)
        banner_print(f"[+] Generating variant neo4j for {cve_id} ...")
        os.makedirs(os.path.join(VARIANT_CODE_RESULTS_NEO4J_DIR, MODEL), exist_ok=True)
        repo_to_neo4j_cpg(variant_code_cve, os.path.join(VARIANT_CODE_RESULTS_NEO4J_DIR, MODEL))


    
    for cve_id in os.listdir(os.path.join(VARIANT_CODE_RESULTS_NEO4J_DIR, MODEL)):

        cve_variant_signature_dir = os.path.join(sig_generate_dir, "variant_signature_results", MODEL, f"{cve_id}_variant_sig_info")
        if os.path.exists(cve_variant_signature_dir) and os.path.exists(os.path.join(cve_variant_signature_dir, f"{cve_id}_variant_prepatch_final_sink_context.json")):
            print(f"[+] {cve_variant_signature_dir} already exists. skip variant sig generation ...")
            continue

        cve_neo4j_path = os.path.join(VARIANT_CODE_RESULTS_NEO4J_DIR, MODEL, cve_id)
        if cve_id in cve_id_to_vuln_type:   
            vuln_type = str(VULN_TYPE_STR_TO_DIGIT_DICT[cve_collection[cve_id_to_vuln_type[cve_id]][cve_id]['vuln_type']])
            existing_entry = next(
                (e for e in potential_sink_funcname_data[vuln_type]
                if str(e.get('cve_id')) == str(cve_id)),
                None
            )
            potential_sink_funcname_list = existing_entry.get('potential_sink_funcname_list', [])
            potential_source_funcname_list = potential_source_funcname_data.get(cve_id, [])
        elif cve_id in cve_1201_collection['sql_injection']:
            vuln_type = str(VULN_TYPE_STR_TO_DIGIT_DICT['sql_injection'])
            potential_sink_funcname_list = cve_1201_collection['sql_injection'][cve_id]['sink']['function_name']
            if type(potential_sink_funcname_list) is not list:
                potential_sink_funcname_list = [potential_sink_funcname_list]
            potential_source_funcname_list = cve_1201_collection['sql_injection'][cve_id]['source']['function_name']
            if potential_source_funcname_list in {"_POST", "_GET", "_REQUEST", "_FILES", "_COOKIE"}:
                potential_source_funcname_list = []
            else:
                potential_source_funcname_list = [potential_source_funcname_list]
        elif cve_id in cve_1201_collection['file_upload']:
            vuln_type = str(VULN_TYPE_STR_TO_DIGIT_DICT['file_upload'])
            potential_sink_funcname_list = cve_1201_collection['file_upload'][cve_id]['sink']['function_name']
            if type(potential_sink_funcname_list) is not list:
                potential_sink_funcname_list = [potential_sink_funcname_list]
            potential_source_funcname_list = cve_1201_collection['file_upload'][cve_id]['source']['function_name']
            if potential_source_funcname_list in {"_POST", "_GET", "_REQUEST", "_FILES", "_COOKIE"}:
                potential_source_funcname_list = []
            else:
                potential_source_funcname_list = [potential_source_funcname_list]


        change_conn_port(os.path.join(cve_neo4j_path, "conf/neo4j.conf"), "7690", "7476")
        # start_databases_with_database(cve_neo4j_path, f"{cve_id}_variant_sig_db")
        run_sig_source_sink(f"{cve_id}_prepatch", potential_source_funcname_list, 
                            extend_vuln_model={int(vuln_type): potential_sink_funcname_list}, 
                            task="variant", cve_id=cve_id, neoconfig_path=VARIANT_NEO4J_CONFIG, model=MODEL)


if __name__ == "__main__":
    signature_results_sig_info = "./hydra/sig_gene_results/signature_results"

    main()