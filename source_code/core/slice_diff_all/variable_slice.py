import os
import sys
sys.path.append("")
import ground_truth.slice_diff_all.utils as utils
from ground_truth.slice_diff_all.common import Language
import hashlib
import ground_truth.slice_diff_all.hunkmap as hunkmap
from os.path import join, exists
from ground_truth.slice_diff_all.project import Method, Project
from ground_truth.slice_diff_all.codefile import CodeFile, create_code_tree


cve_8637_diff = "./storage/patch_analysis_result/diff"
cve_8637_code = "./php-cve-dataset/d99bd8277d384f3417e917ce20bef5d061110343_v1"


def variable_slice(cveid, cve_code_path):
    file_name = os.path.basename(cve_code_path)
    file_path_md5 = hashlib.md5(cve_code_path.encode()).hexdigest()[:4]
    method_name = "change_parent"
    cache_dir = f"cache_bug/{cveid}/{file_name}#{method_name}#{file_path_md5}"
    os.makedirs(cache_dir, exist_ok=True)

    pre_file_path = join(cve_code_path, "prepatch", "code")
    for code in os.listdir(pre_file_path):
        if code.endswith(".php"):
            pre_file_path = join(pre_file_path, code)
            break
    post_file_path = join(cve_code_path, "postpatch", "code")
    for code in os.listdir(post_file_path):
        if code.endswith(".php"):
            post_file_path = join(post_file_path, code)
            break   
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

    origin_before_func_code = open(pre_file_path, "r", encoding="utf-8").read()
    origin_after_func_code = open(post_file_path, "r", encoding="utf-8").read()

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
    pre_post_line_map, pre_post_hunk_map, pre_post_add_lines, re_post_del_lines = hunkmap.method_map(pre_method, post_method)

    post_pre_line_map = {v: k for k, v in pre_post_line_map.items()}

    backward_slice_level = slice_level
    forward_slice_level = slice_level
    try:
        taint_variable = ["$node_id"]
        pre_slice_results = pre_method.slice_by_diff_lines(backward_slice_level, forward_slice_level, need_criteria_identifier=True, criteria_identifier_list=taint_variable, write_dot=True)
        # post_slice_results = post_method.slice_by_diff_lines(backward_slice_level, forward_slice_level, need_criteria_identifier=True, write_dot=True)
        if pre_slice_results is None:
            print("[!] Variable slice failed, no results found. [prepatch]")
        post_slice_results = None
        if post_slice_results is None:
            print("[!] Variable slice failed, no results found. [postpatch]")
    except KeyError:
        return


def main():
    variable_slice("CVE-2023-8637")

if __name__ == "__main__":
    main()