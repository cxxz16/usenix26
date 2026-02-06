import os
import sys
import subprocess
sys.path.append("")
import ground_truth.slice_diff_all.utils as utils
import hashlib
import ground_truth.slice_diff_all.hunkmap as hunkmap
from os.path import join, exists
from ground_truth.slice_diff_all.common import Language
from ground_truth.slice_diff_all.project import Method, Project
from ground_truth.slice_diff_all.codefile import CodeFile, create_code_tree
from ground_truth.slice_diff_all.ts_code_process import vuln_code_extract


cve_8637_diff = "./storage/patch_analysis_result/diff"
cve_8637_code = "./php-cve-dataset/d99bd8277d384f3417e917ce20bef5d061110343_v1"
cve_22727_code = "./php-cve-dataset/CVE-2023-22727"


def statement_slice(cve_id, method_name, cve_code_path):
    file_name = os.path.basename(cve_code_path)
    file_path_md5 = hashlib.md5(cve_code_path.encode()).hexdigest()[:4]

    pre_code_dir = join(cve_code_path, "prepatch", "code")
    for code in os.listdir(pre_code_dir):
        if code.endswith(".php"):
            pre_file_path = join(pre_code_dir, code)
            break
    post_code_dir = join(cve_code_path, "postpatch", "code")
    for code in os.listdir(post_code_dir):
        if code.endswith(".php"):
            post_file_path = join(post_code_dir, code)
            break
    
    if method_name is None:
        return "False", open(pre_file_path, "r", encoding="utf-8").read()

    method_name = method_name
    cache_dir = f"cache_bug/{cve_id}/{file_name}#{method_name}#{file_path_md5}"
    os.makedirs(cache_dir, exist_ok=True)
    #  
    if not os.path.exists(join(cve_code_path, "prepatch", "code_back")):
        subprocess.run(['cp', '-r', pre_code_dir, join(cve_code_path, "prepatch", "code_back")])
        vuln_code_extract(pre_file_path, method_name, pre_file_path)
    else:
        print(f"[+] prepatch code {pre_file_path} already exists, skip extracting.")
    if not os.path.exists(join(cve_code_path, "postpatch", "code_back")):
        subprocess.run(['cp', '-r', post_code_dir, join(cve_code_path, "postpatch", "code_back")])
        vuln_code_extract(post_file_path, method_name, post_file_path)
    else:
        print(f"[+] postpatch code {post_file_path} already exists, skip extracting.")

    origin_before_func_code = open(pre_file_path, "r", encoding="utf-8").read()
    origin_after_func_code = open(post_file_path, "r", encoding="utf-8").read()
    vuln_code_lines = origin_before_func_code.count("\n")
    if vuln_code_lines < 50:
        print("[+] The vulnerable function is too short, no need to slice.")
        return "False", origin_before_func_code
    
    # return

    pre_dir=join(cve_code_path, "prepatch")
    post_dir=join(cve_code_path, "postpatch")
    utils.export_joern_graph(
        pre_dir=join(cve_code_path, "prepatch"),
        post_dir=join(cve_code_path, "postpatch"),
        need_cdg=False,
        language=Language.PHP,
        multiprocess=False, overwrite=False
    )

    overwrite = False

    pre_codefile = CodeFile(os.path.basename(pre_file_path), origin_before_func_code)
    post_codefile = CodeFile(os.path.basename(post_file_path), origin_after_func_code)
    create_code_tree([pre_codefile], pre_dir, overwrite=overwrite)
    create_code_tree([post_codefile], post_dir, overwrite=overwrite)

    language = Language.PHP
    pre_project = Project("1.pre", [pre_codefile], language)
    post_project = Project("2.post", [post_codefile], language)

    pre_project.load_joern_graph(f"{pre_dir}/cpg", f"{pre_dir}/pdg")
    post_project.load_joern_graph(f"{post_dir}/cpg", f"{post_dir}/pdg")

    file_name = pre_file_path.split("/")[-1]
    vuln_method_signature = f"{file_name}#{method_name}"
    file_name = post_file_path.split("/")[-1]
    fix_method_signature = f"{file_name}#{method_name}"
    pre_method = Project.get_methods(pre_project, vuln_method_signature)
    post_method = Project.get_methods(post_project, fix_method_signature)
    double_methods = [pre_method, post_method]
    slice_level = 1
    pre_method.counterpart = post_method
    post_method.counterpart = pre_method
    method_dir = Method.init_method_double_dir(double_methods, cache_dir, slice_level)

    only_add = hunkmap.check_diff(pre_method, post_method)
    if only_add:
        return "False", origin_before_func_code
    pre_post_line_map, pre_post_hunk_map, pre_post_add_lines, re_post_del_lines = hunkmap.method_map(pre_method, post_method)

    post_pre_line_map = {v: k for k, v in pre_post_line_map.items()}

    backward_slice_level = slice_level
    forward_slice_level = slice_level
    try:
        pre_slice_results = pre_method.slice_by_diff_lines(backward_slice_level, forward_slice_level, write_dot=True)
        # post_slice_results = post_method.slice_by_diff_lines(backward_slice_level, forward_slice_level, write_dot=True)
        return "True", pre_slice_results[3]
    except KeyError:
        return "False", origin_before_func_code


def main():
    statement_slice("CVE-2022-22727", "change_parent", cve_22727_code)

if __name__ == "__main__":
    main()