import os
import subprocess
import sys
sys.path.append("")
import ground_truth.slice_diff_all.cpu_heater as cpu_heater
# import joern
import ground_truth.slice_diff_all.joern as joern
from ground_truth.slice_diff_all.common import Language
import configparser
config = configparser.ConfigParser()
config.read("./ground_truth/slice_diff_all/config.ini")

joern2_path = config["path"]["joern2_path"]
# joern.set_joern_env(joern4_path)

print(subprocess.run(['which', 'joern'], stdout=subprocess.PIPE).stdout.decode().strip())

def export_joern_graph(pre_dir: str, post_dir: str, need_cdg: bool, language: Language, multiprocess: bool = False, overwrite: bool = False):
    worker_args = [
        (f"{pre_dir}/code", pre_dir, language, need_cdg, overwrite),
        (f"{post_dir}/code", post_dir, language, need_cdg, overwrite),
    ]
    if multiprocess:
        cpu_heater.multiprocess(worker_args, joern.export_with_preprocess_and_merge, max_workers=2, show_progress=False)
    else:
        joern.export_with_preprocess_and_merge(*worker_args[0])
        joern.export_with_preprocess_and_merge(*worker_args[1])


def export_joern_graph_pre_post(pre_dir: str, post_dir: str, need_cdg: bool, language: Language, multiprocess: bool = False, overwrite: bool = False):
    worker_args = [
        (f"{pre_dir}/analysis", pre_dir, language, need_cdg, overwrite),
        (f"{post_dir}/analysis", post_dir, language, need_cdg, overwrite)
    ]
    if multiprocess:
        cpu_heater.multiprocess(worker_args, joern.export_with_preprocess_and_merge, max_workers=3, show_progress=False)
    else:
        joern.export_with_preprocess_and_merge(*worker_args[0])
        joern.export_with_preprocess_and_merge(*worker_args[1])


def group_consecutive_ints(nums: list[int]) -> list[list[int]]:
    if len(nums) == 0:
        return []
    nums.sort()
    result = [[nums[0]]]
    for num in nums[1:]:
        if num == result[-1][-1] + 1:
            result[-1].append(num)
        else:
            result.append([num])
    return result


def recursive_parent_find(path: str, filename: str, all_files: list[str]) -> str | None:
    while True:
        if os.path.join(path, filename) in all_files:
            return path
        if path == "" or path == "/":
            return None
        path = os.path.dirname(path)


def line2offset(text: str, line: int) -> int:
    return len("\n".join(text.split("\n")[:line - 1]))


def exact_match(a: str, b: str) -> bool:
    if a == b:
        return True
    a = format.normalize(a, del_comments=False)
    b = format.normalize(b, del_comments=False)
    return a == b
