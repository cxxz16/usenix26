import os
import json
import pickle
import Levenshtein
from hydra_utils import *
from utils4 import llm_for_fp_prun

ORIGIN_SLICE_CODE_DIR = "./detection_inter_slice_result_0120_papers_all_files/"
SIG_DATABASE = "./hydra/sig_database"
KNOWN_VULN_SIG_DB = "./hydra/sig_gene_results/signature_results"
VARIANT_VULN_SIG_DB = "./hydra/sig_gene_results/variant_signature_results"
POTENTIAL_SINKS_DETECTION_DIR = "./potential_sinks_detection_0120_papers"
DETECTION_REPORT_DIR = "./hydra/detection_report"

FINAL_SIG_DB_FROM_KNOWN_VULN = "./hydra/sig_database/known/signature_db_reorganized.json"
FINAL_SIG_DB_FROM_VARIANT = "./hydra/sig_database/variant/signature_db_reorganized.json"

if os.path.exists(FINAL_SIG_DB_FROM_KNOWN_VULN):
    with open(FINAL_SIG_DB_FROM_KNOWN_VULN, "r", encoding="utf-8") as f:
        VULN_SIGNATURE_DATABASE = json.load(f)
else:
    VULN_SIGNATURE_DATABASE = dict()

if os.path.exists(FINAL_SIG_DB_FROM_VARIANT):
    with open(FINAL_SIG_DB_FROM_VARIANT, "r", encoding="utf-8") as f:
        VULN_VARIANT_SIGNATURE_DATABASE = json.load(f)
else:
    VULN_VARIANT_SIGNATURE_DATABASE = dict()



VULN_TYPE_TO_STR_DICT = {
    7: 'File_Include',
    2: 'File_Read',
    1: 'File_Delete',
    12: 'File_Write',
    10: 'XSS',
    4: 'Command_Injection',
    3: 'Code_Injection',
    6: 'File_Upload',
    13: 'Open_Redirect',
    8: 'PHP_Object_Injection',
    9: 'SQL_Injection'
}


STR_TO_VULN_TYPE_DICT = {v: k for k, v in VULN_TYPE_TO_STR_DICT.items()}


def get_sink_location(repo, sink, vuln_type_num):
    potential_sink_pkl = os.path.join(POTENTIAL_SINKS_DETECTION_DIR, f"{repo}.pkl")
    potential_sink_data = pickle.load(open(potential_sink_pkl, "rb"))
    print("db")

    vt_sink_datas = potential_sink_data.get(vuln_type_num, {})
    for vt_sink_data in vt_sink_datas:
        if str(vt_sink_data.node_id) == str(sink):
            return vt_sink_data.file_name, vt_sink_data.lineno

    return None, None


MODEL = "" 
def is_signature_duplicate(sig, existing_sigs):
    sig_str = json.dumps(sig, sort_keys=True, ensure_ascii=False)
    for existing_sig in existing_sigs:
        if json.dumps(existing_sig, sort_keys=True, ensure_ascii=False) == sig_str:
            return True
    return False

def vuln_signature_database():
    global VULN_SIGNATURE_DATABASE
    
    print("\n" + "=" * 80)
    print("Building KNOWN Vulnerability Signature Database")
    print("=" * 80)
    
    stats = {
        'total_cves': 0,
        'new_cves': 0,
        'total_sigs': 0,
        'new_sigs': 0,
        'existing_sigs': 0,
        'filtered_sigs': 0  
    }
    
    for vuln_type, cve_dict in VULN_SIGNATURE_DATABASE.items():
        for cve_id, sig_list in cve_dict.items():
            stats['existing_sigs'] += len(sig_list)
    
    if not os.path.exists(KNOWN_VULN_SIG_DB):
        print(f"[-] Warning: Known vulnerability signature directory not found: {KNOWN_VULN_SIG_DB}")
        return
    
    for cve_sig_info in sorted(os.listdir(KNOWN_VULN_SIG_DB)):
        if not cve_sig_info.endswith("_sig_info"):
            continue
        
        cve_id = cve_sig_info.replace("_sig_info", "")
        cve_sig_path = os.path.join(KNOWN_VULN_SIG_DB, cve_sig_info, f"{cve_id}_prepatch_final_sink_context.json")
        
        if not os.path.exists(cve_sig_path):
            continue
        
        # 读取CVE签名文件
        with open(cve_sig_path, "r", encoding="utf-8") as f:
            cve_sig = json.load(f)
        
        cve_new_sigs = 0  
        
        for cross_mode, vt_sinkid in cve_sig.items():
            for vuln_type, sink_sig_dict in vt_sinkid.items():
                if vuln_type not in VULN_SIGNATURE_DATABASE:
                    VULN_SIGNATURE_DATABASE[vuln_type] = {}
                
                if cve_id not in VULN_SIGNATURE_DATABASE[vuln_type]:
                    VULN_SIGNATURE_DATABASE[vuln_type][cve_id] = []
                    stats['new_cves'] += 1
                
                for sink_id, sig_list in sink_sig_dict.items():
                    for sig in sig_list:
                        has_source = any("$Source" in str(s) for s in sig)
                        if not has_source:
                            stats['filtered_sigs'] += 1
                            continue 
                        
                        if not is_signature_duplicate(sig, VULN_SIGNATURE_DATABASE[vuln_type][cve_id]):
                            VULN_SIGNATURE_DATABASE[vuln_type][cve_id].append(sig)
                            stats['new_sigs'] += 1
                            cve_new_sigs += 1
        
        if cve_new_sigs > 0:
            print(f"  [+] {cve_id}: Added {cve_new_sigs} new signatures")
    
    for vuln_type, cve_dict in VULN_SIGNATURE_DATABASE.items():
        stats['total_cves'] += len(cve_dict)
        for cve_id, sig_list in cve_dict.items():
            stats['total_sigs'] += len(sig_list)
    
    os.makedirs(os.path.dirname(FINAL_SIG_DB_FROM_KNOWN_VULN), exist_ok=True)
    with open(FINAL_SIG_DB_FROM_KNOWN_VULN, "w", encoding="utf-8") as f:
        json.dump(VULN_SIGNATURE_DATABASE, f, indent=4, ensure_ascii=False)
    
    print("\n" + "-" * 80)
    print("KNOWN Signature Database Statistics:")
    print(f"  Total CVEs: {stats['total_cves']} (New: {stats['new_cves']})")
    print(f"  Total Signatures: {stats['total_sigs']} (Existing: {stats['existing_sigs']}, New: {stats['new_sigs']})")
    print(f"  Filtered (no $Source): {stats['filtered_sigs']}")
    print(f"  Database saved to: {FINAL_SIG_DB_FROM_KNOWN_VULN}")
    print("-" * 80)


def variant_signature_database():
    global VARIANT_VULN_SIG_DB, VULN_VARIANT_SIGNATURE_DATABASE
    
    print("\n" + "=" * 80)
    print("Building VARIANT Signature Database")
    print("=" * 80)
    stats = {
        'total_cves': 0,
        'new_cves': 0,
        'total_sigs': 0,
        'new_sigs': 0,
        'existing_sigs': 0,
        'filtered_sigs': 0  
    }
    
    for vuln_type, cve_dict in VULN_VARIANT_SIGNATURE_DATABASE.items():
        for cve_id, sig_list in cve_dict.items():
            stats['existing_sigs'] += len(sig_list)
    
    if MODEL:
        variant_db_path = os.path.join(VARIANT_VULN_SIG_DB, MODEL)
    else:
        variant_db_path = VARIANT_VULN_SIG_DB
    
    if not os.path.exists(variant_db_path):
        print(f"[-] Warning: Variant signature directory not found: {variant_db_path}")
        return
    
    print(f"[+] Loading from: {variant_db_path}")
    
    for cve_sig_info in sorted(os.listdir(variant_db_path)):
        if not cve_sig_info.endswith("_variant_sig_info"):
            continue
        
        cve_id = cve_sig_info.replace("_variant_sig_info", "")
        cve_sig_path = os.path.join(variant_db_path, cve_sig_info, f"{cve_id}_prepatch_final_sink_context.json")
        
        if not os.path.exists(cve_sig_path):
            continue
        
        with open(cve_sig_path, "r", encoding="utf-8") as f:
            cve_sig = json.load(f)
        
        cve_new_sigs = 0  
        
        for cross_mode, vt_sinkid in cve_sig.items():
            for vuln_type, sink_sig_dict in vt_sinkid.items():
                if vuln_type not in VULN_VARIANT_SIGNATURE_DATABASE:
                    VULN_VARIANT_SIGNATURE_DATABASE[vuln_type] = {}
                
                if cve_id not in VULN_VARIANT_SIGNATURE_DATABASE[vuln_type]:
                    VULN_VARIANT_SIGNATURE_DATABASE[vuln_type][cve_id] = []
                    stats['new_cves'] += 1
                
                for sink_id, sig_list in sink_sig_dict.items():
                    for sig in sig_list:
                        has_source = any("$Source" in str(s) for s in sig)
                        if not has_source:
                            stats['filtered_sigs'] += 1
                            continue 
                        
                        if not is_signature_duplicate(sig, VULN_VARIANT_SIGNATURE_DATABASE[vuln_type][cve_id]):
                            VULN_VARIANT_SIGNATURE_DATABASE[vuln_type][cve_id].append(sig)
                            stats['new_sigs'] += 1
                            cve_new_sigs += 1
        
        if cve_new_sigs > 0:
            print(f"  [+] {cve_id}: Added {cve_new_sigs} new signatures")
    
    for vuln_type, cve_dict in VULN_VARIANT_SIGNATURE_DATABASE.items():
        stats['total_cves'] += len(cve_dict)
        for cve_id, sig_list in cve_dict.items():
            stats['total_sigs'] += len(sig_list)
    
    os.makedirs(os.path.dirname(FINAL_SIG_DB_FROM_VARIANT), exist_ok=True)
    with open(FINAL_SIG_DB_FROM_VARIANT, "w", encoding="utf-8") as f:
        json.dump(VULN_VARIANT_SIGNATURE_DATABASE, f, indent=4, ensure_ascii=False)
    
    print("\n" + "-" * 80)
    print("VARIANT Signature Database Statistics:")
    print(f"  Total CVEs: {stats['total_cves']} (New: {stats['new_cves']})")
    print(f"  Total Signatures: {stats['total_sigs']} (Existing: {stats['existing_sigs']}, New: {stats['new_sigs']})")
    print(f"  Filtered (no $Source): {stats['filtered_sigs']}")
    print(f"  Database saved to: {FINAL_SIG_DB_FROM_VARIANT}")
    print("-" * 80)


def clean_vuln_variant_sigdb():
    print("\n[+] Cleaning VARIANT signature database (removing non-$Source signatures)...")
    removed_count = 0
    
    for vuln_type in list(VULN_VARIANT_SIGNATURE_DATABASE.keys()):
        for cve_id in list(VULN_VARIANT_SIGNATURE_DATABASE[vuln_type].keys()):
            cleaned_sigs = []
            for sig in VULN_VARIANT_SIGNATURE_DATABASE[vuln_type][cve_id]:
                has_source = any("$Source" in str(s) for s in sig)
                if has_source:
                    cleaned_sigs.append(sig)
                else:
                    removed_count += 1
            
            if cleaned_sigs:
                VULN_VARIANT_SIGNATURE_DATABASE[vuln_type][cve_id] = cleaned_sigs
            else:
                del VULN_VARIANT_SIGNATURE_DATABASE[vuln_type][cve_id]
        
        if not VULN_VARIANT_SIGNATURE_DATABASE[vuln_type]:
            del VULN_VARIANT_SIGNATURE_DATABASE[vuln_type]
    
    print(f"    Removed {removed_count} signatures without $Source")

    with open(FINAL_SIG_DB_FROM_VARIANT, "w", encoding="utf-8") as f:
        json.dump(VULN_VARIANT_SIGNATURE_DATABASE, f, indent=4, ensure_ascii=False)
    print(f"    Cleaned database saved to: {FINAL_SIG_DB_FROM_VARIANT}")


def clean_vuln_known_sigdb():
    print("\n[+] Cleaning KNOWN signature database (removing non-$Source signatures)...")
    removed_count = 0
    
    for vuln_type in list(VULN_SIGNATURE_DATABASE.keys()):
        for cve_id in list(VULN_SIGNATURE_DATABASE[vuln_type].keys()):
            cleaned_sigs = []
            for sig in VULN_SIGNATURE_DATABASE[vuln_type][cve_id]:
                has_source = any("$Source" in str(s) for s in sig)
                if has_source:
                    cleaned_sigs.append(sig)
                else:
                    removed_count += 1
            
            if cleaned_sigs:
                VULN_SIGNATURE_DATABASE[vuln_type][cve_id] = cleaned_sigs
            else:
                del VULN_SIGNATURE_DATABASE[vuln_type][cve_id]
        
        if not VULN_SIGNATURE_DATABASE[vuln_type]:
            del VULN_SIGNATURE_DATABASE[vuln_type]
    
    print(f"    Removed {removed_count} signatures without $Source")

    with open(FINAL_SIG_DB_FROM_KNOWN_VULN, "w", encoding="utf-8") as f:
        json.dump(VULN_SIGNATURE_DATABASE, f, indent=4, ensure_ascii=False)
    print(f"    Cleaned database saved to: {FINAL_SIG_DB_FROM_KNOWN_VULN}")


def sig_match(vuln_type, potential_signatures, signature_db):
    for vt in signature_db.keys():

        cve_dict = signature_db[vt]
        
        for cve_id, cve_sig_list in cve_dict.items():
            for cve_sig in cve_sig_list:
                for cve_sig_str in cve_sig:
                    if not isinstance(cve_sig_str, str):
                        continue
                    
                    for potential_sig in potential_signatures:
                        for potential_sig_str in potential_sig:
                            if not isinstance(potential_sig_str, str):
                                continue
                            
                            if "$Source" not in potential_sig_str:
                                continue
                            
                            similarity_score = Levenshtein.jaro(potential_sig_str, cve_sig_str)
                            
                            if similarity_score >= 0.85:
                                return True, potential_sig_str, cve_sig_str, similarity_score, cve_id
    
    return False, None, None, None, None


def vuln_clone_detection(target_repo_path, detection_mode, redetect=False):
    VARIANT_DETECTION = (detection_mode == "variant") 
    if VARIANT_DETECTION:
        sig_DB = VULN_VARIANT_SIGNATURE_DATABASE
        db_type = 'variant'
    else:
        sig_DB = VULN_SIGNATURE_DATABASE
        db_type = 'original'

    report_path = os.path.join(DETECTION_REPORT_DIR, f"{target_repo_path}_detection_report_{db_type}.json")
    
    if os.path.exists(report_path) and not redetect:
        print(f"[+] Detection report already exists at {report_path}, loading...")
        return report_path

    print(f"\n[+] Starting vulnerability clone detection for: {target_repo_path}")
    print(f"[+] Using {db_type.upper()} signature database")

    detection_signature_db_path = "./detection_result_signature_0120_papers_final"
    target_repo_signature_path = os.path.join(detection_signature_db_path, f"{target_repo_path}_prepatch_final_sink_context.json")
    
    if not os.path.exists(target_repo_signature_path):
        print(f"[-] Error: Target repository signature file not found: {target_repo_signature_path}")
        return None
    
    with open(target_repo_signature_path, "r", encoding="utf-8") as f:
        target_repo_signatures = json.load(f)

    matched_sig_record = {}  # vuln_type_str -> list of matched records
    repo = f"{target_repo_path}_prepatch"
    
    total_sinks_checked = 0
    total_matches_found = 0

    for cross_mode, vt_sinkid in target_repo_signatures.items():
        print(f"\n[+] Processing {cross_mode} mode...")
        
        for vuln_type, sink_sig_dict in vt_sinkid.items():
            vuln_type_str = VULN_TYPE_TO_STR_DICT.get(int(vuln_type), vuln_type)

            for sink_id, file_sig_dict in sink_sig_dict.items():
                if not isinstance(file_sig_dict, dict):
                    continue
                
                for potential_vuln_sink_path, sig_context in file_sig_dict.items():
                    total_sinks_checked += 1
                    
                    code_vuln_type = potential_vuln_sink_path.split("/")[-2]
                    file_idx = potential_vuln_sink_path.split("/")[-1]
                    origin_sink_id = file_idx.split("_")[0]
                    
                    origin_sink_code_path = os.path.join(
                        ORIGIN_SLICE_CODE_DIR, 
                        repo, 
                        vuln_type, 
                        f"sink_{origin_sink_id}", 
                        f"src_sink_path_{file_idx}"
                    )
                    
                    if not sig_context or not isinstance(sig_context, list):
                        continue
                    
                    matched, potential_sig, matched_sig, score, cve_id = sig_match(
                        vuln_type, sig_context, sig_DB
                    )
                    
                    if matched:
                        total_matches_found += 1
                        print(f"  [✓] Match found!")
                        print(f"      Sink: {potential_vuln_sink_path}")
                        print(f"      Potential Sig: {potential_sig}")
                        print(f"      Matched Sig: {matched_sig}")
                        print(f"      Similarity: {score:.4f}")
                        print(f"      CVE: {cve_id}")
                        
                        if code_vuln_type not in matched_sig_record:
                            matched_sig_record[code_vuln_type] = []
                        
                        matched_sig_record[code_vuln_type].append({
                            "potential_signature": potential_sig,
                            "matched_signature": matched_sig,
                            "similarity_score": score,
                            "origin_sink_code_path": origin_sink_code_path,
                            "origin_sink_id": origin_sink_id,
                            "repo": repo,
                            "sink_path": potential_vuln_sink_path,
                            "origin_cve_id": cve_id,
                            "vuln_type": vuln_type_str,
                            "cross_mode": cross_mode
                        })

    os.makedirs(DETECTION_REPORT_DIR, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(matched_sig_record, f, indent=4, ensure_ascii=False)

    print("\n" + "=" * 80)
    print("Detection Summary:")
    print(f"  Total sinks checked: {total_sinks_checked}")
    print(f"  Total matches found: {total_matches_found}")
    print(f"  Vulnerability types with matches: {len(matched_sig_record)}")
    
    for vuln_type_str, matches in matched_sig_record.items():
        print(f"    [{vuln_type_str}]: {len(matches)} matches")
    
    print(f"\n[+] Detection report saved to: {report_path}")
    print("=" * 80)
    
    return report_path

def FP_reduce_prepare(matched_sig_record_path):
    matched_sig_record = json.load(open(matched_sig_record_path, "r", encoding="utf-8"))
    fp_analysis = []  
    for vuln_type, sig_records in matched_sig_record.items():
        for record in sig_records:
            origin_vuln_code_path = record["origin_sink_code_path"]
            origin_sink = record["origin_sink_id"]
            repo = record["repo"]
            vuln_type_num = STR_TO_VULN_TYPE_DICT.get(vuln_type)
            origin_sink_file, origin_sink_lineno = get_sink_location(repo, origin_sink, vuln_type_num)
            if "/9/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/9/", "/SQL_Injection/")
            elif "/10/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/10/", "/XSS/")
            elif "/2/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/2/", "/File_Read/")
            elif "/1/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/1/", "/File_Delete/")
            elif "/12/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/12/", "/File_Write/")
            elif "/4/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/4/", "/Command_Injection/")
            elif "/3/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/3/", "/Code_Injection/")
            elif "/7/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/7/", "/File_Include/")
            elif "/6/" in origin_vuln_code_path:
                origin_vuln_code_path = origin_vuln_code_path.replace("/6/", "/File_Upload/")

            try:
                origin_context = extract_file_function([Path(origin_vuln_code_path)])
                context_content = {k: sorted(list(v)) for k, v in origin_context.items()}     
                if context_content == {}:
                    context_content = {origin_vuln_code_path: []}
                fp_analysis.append({
                    "vuln_type": vuln_type,
                    "repo": repo,
                    "origin_sink_file": origin_sink_file,
                    "origin_sink_lineno": origin_sink_lineno,
                    "origin_context": context_content,
                })
            except Exception as e:
                print(f"[-] Error extracting context from {origin_vuln_code_path}: {e}")

    fp_report_path = os.path.join(DETECTION_REPORT_DIR, f"{repo}_prepare_for_fp_analysis_report_2.json")
    with open(fp_report_path, "w", encoding="utf-8") as f:
        json.dump(fp_analysis, f, indent=4, ensure_ascii=False)

    return fp_report_path


def print_signature_database_stats():
    print("\n" + "=" * 80)
    print("Loaded Signature Database Statistics")
    print("=" * 80)
    
    print("\nKNOWN Vulnerability Signatures:")
    if VULN_SIGNATURE_DATABASE:
        total_known_cves = 0
        total_known_sigs = 0
        for vuln_type, cve_dict in VULN_SIGNATURE_DATABASE.items():
            vuln_type_name = VULN_TYPE_TO_STR_DICT.get(int(vuln_type), vuln_type)
            cve_count = len(cve_dict)
            sig_count = sum(len(sig_list) for sig_list in cve_dict.values())
            total_known_cves += cve_count
            total_known_sigs += sig_count
            print(f"  [{vuln_type_name}] CVEs: {cve_count}, Signatures: {sig_count}")
        print(f"  Total: {total_known_cves} CVEs, {total_known_sigs} signatures")
    else:
        print("  No known vulnerability signatures loaded")
    
    print("\nVARIANT Signatures:")
    if VULN_VARIANT_SIGNATURE_DATABASE:
        total_variant_cves = 0
        total_variant_sigs = 0
        for vuln_type, cve_dict in VULN_VARIANT_SIGNATURE_DATABASE.items():
            vuln_type_name = VULN_TYPE_TO_STR_DICT.get(int(vuln_type), vuln_type)
            cve_count = len(cve_dict)
            sig_count = sum(len(sig_list) for sig_list in cve_dict.values())
            total_variant_cves += cve_count
            total_variant_sigs += sig_count
            print(f"  [{vuln_type_name}] CVEs: {cve_count}, Signatures: {sig_count}")
        print(f"  Total: {total_variant_cves} CVEs, {total_variant_sigs} signatures")
    else:
        print("  No variant signatures loaded")
    
    print("=" * 80 + "\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Vulnerability Detection")
    parser.add_argument("--repo", type=str, required=True, help="Specify the repository to detect")
    parser.add_argument("--build-db", action="store_true", 
                        help="Build/update signature databases from CVE files (only needed when adding new signatures)")
    parser.add_argument("--det-mode", type=str, choices=["known", "variant"], default="variant",
                        help="Choose which signature database to use for detection")
    parser.add_argument("--redetect", action="store_true", 
                        help="Redetect even if a report already exists")
    args = parser.parse_args()
    target_repo = args.repo
    detection_mode = args.det_mode
    redetect = args.redetect

    if args.build_db:
        print("[+] Building signature databases from CVE files...")
        vuln_signature_database()
        variant_signature_database()
    else:
        print("[+] Using existing signature databases (use --build-db to rebuild)")
        print_signature_database_stats()


    print(f"\n[+] Starting vulnerability detection for repository: {target_repo}")
    report_path = vuln_clone_detection(target_repo, detection_mode, redetect=redetect)

    if detection_mode == "variant":
        fp_report_path = FP_reduce_prepare(report_path)
        llm_for_fp_prun(target_repo, fp_report_path)


if __name__ == "__main__":
    main()

