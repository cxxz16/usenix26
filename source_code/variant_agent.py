
from core.chat import openai_chat
from typing import List
import os
import json
from hydra_utils import add_line_numbers, get_cve_description, parse_vuln_answer, banner_print


VARIANT_CODE_DIR = "./hydra/sig_gene_results/variant_results/variant_code"
VARIANT_STRATEGY_DIR = "./hydra/sig_gene_results/variant_results/variant_strategy"
os.makedirs(VARIANT_CODE_DIR, exist_ok=True)
os.makedirs(VARIANT_STRATEGY_DIR, exist_ok=True)

PROMPT_DIR = "./hydra/prompts"
def vuln_check(cve_id, source_code_filepath, model="gpt-5"):
    # 对生成的变体进行漏洞存在性验证
    with open(source_code_filepath, "r", encoding="utf-8") as f:
        source_code = f.read()
    source_code = add_line_numbers(source_code)

    if "_" in cve_id:
        cve_id = cve_id.split("_")[0]
    cve_desc = get_cve_description(cve_id)

    vuln_check_prompt = open(os.path.join(PROMPT_DIR, "r2_vuln_check_prompt.md"), "r").read()
    vuln_check_prompt = vuln_check_prompt.replace("{{SOURCE_CODE}}", source_code)
    vuln_check_prompt = vuln_check_prompt.replace("{{VULNERABILITY_DESCRIPTION}}", cve_desc)

    response = openai_chat(vuln_check_prompt, temperature=0.1, model=model)
    is_vulnerable = parse_vuln_answer(response)

    return True if is_vulnerable else False


def mutate_complete(cve_id, source_code_filepath, dataflow_str, sink_funcname, model="gpt-5", var_count=1, api_key=None):
    # 默认为每个 source code 生成 var_count 个变体
    # code 和 strategy 的文件名： folder/cve_id/src_idx_varint_{idx}.php  | folder/cve_id/src_idx_strategy_{idx}.txt
    response = ""
    with open(source_code_filepath, "r", encoding="utf-8") as f:
        source_code = f.read()
    source_code = add_line_numbers(source_code)

    src_code_idx = os.path.basename(source_code_filepath).split(".")[0]  # 0_0.php -> 0_0

    for i in range(var_count):
        os.makedirs(os.path.join(VARIANT_STRATEGY_DIR, model, cve_id), exist_ok=True)
        count = os.listdir(os.path.join(VARIANT_STRATEGY_DIR, model, cve_id))
        var_idx = len([fname for fname in count if fname.startswith(f"{src_code_idx}_strategy_")])
        os.makedirs(os.path.join(VARIANT_CODE_DIR, model, cve_id), exist_ok=True)
        
        # 这里我想加一段逻辑，当某个 idx 的strategy存在，但是 code 不存在时，先跳过 strategy 生成，直接生成 code
        strategy_path = os.path.join(VARIANT_STRATEGY_DIR, model, cve_id, f"{src_code_idx}_strategy_{var_idx}.json")
        code_path = os.path.join(VARIANT_CODE_DIR, model, cve_id, f"{src_code_idx}_variant_{var_idx}_2.php")
        
        mutate_strategy = None
        strategy_wo_code = False
        for idx in range(var_idx):
            strategy_path = os.path.join(VARIANT_STRATEGY_DIR, model, cve_id, f"{src_code_idx}_strategy_{idx}.json")
            code_path = os.path.join(VARIANT_CODE_DIR, model, cve_id, f"{src_code_idx}_variant_{idx}_2.php")
            if os.path.exists(strategy_path) and not os.path.exists(code_path):
                var_idx = idx
                strategy_wo_code = True
                break

        if not strategy_wo_code:
            if var_idx >= var_count:
                banner_print(f"[++] Reached the desired var_count {var_count}, stopping further generation.")
                break
            
        
        strategy_path = os.path.join(VARIANT_STRATEGY_DIR, model, cve_id, f"{src_code_idx}_strategy_{var_idx}.json")
        code_path = os.path.join(VARIANT_CODE_DIR, model, cve_id, f"{src_code_idx}_variant_{var_idx}.php")
        try:
            if os.path.exists(strategy_path) and not os.path.exists(code_path): 
                with open(strategy_path, "r", encoding="utf-8") as f:
                    mutate_strategy = f.read()
                if isinstance(mutate_strategy, str):    
                    s = mutate_strategy.strip()
                    # 可选：去掉 ```json ... ``` 包裹
                    if s.startswith("```"):
                        s = s.split("```", 2)[1] if s.count("```") >= 2 else s
                        s = s.replace("json", "", 1).strip()

                    
                    mutate_strategy = json.loads(s)
                   
                elif not isinstance(mutate_strategy, dict):
                    raise TypeError(f"mutate_strategy{strategy_path} must be dict or JSON str, got {type(mutate_strategy)}")   
                banner_print(f"[+] Loaded existing strategy from {strategy_path}, generating variant code ...")
            else:
                raise FileNotFoundError
        except Exception as e:
            print(f"mutate_strategy is error: {e} {strategy_path}")
            mutate_strategy_prompt = open(os.path.join(PROMPT_DIR, "r2_mutate_strategy.md"), "r").read()
            mutate_strategy_prompt = mutate_strategy_prompt.replace("{{SOURCE_CODE}}", source_code)
            mutate_strategy_prompt = mutate_strategy_prompt.replace("{{DATA_FLOW}}", "\n".join(dataflow_str))
            mutate_strategy_prompt = mutate_strategy_prompt.replace("{{SINK_FUNCNAME}}", sink_funcname)
            banner_print("[+] Generating mutation strategy ...")
            response_strategy = openai_chat(mutate_strategy_prompt, temperature=0.1, model=model, custom_api_key=api_key)
            mutate_strategy = response_strategy
            # 找个位置保存策略

            with open(os.path.join(VARIANT_STRATEGY_DIR, model, cve_id, f"{src_code_idx}_strategy_{var_idx}.json"), "w", encoding="utf-8") as f:
                f.write(mutate_strategy)

            if isinstance(mutate_strategy, str):
                s = mutate_strategy.strip()
                # 可选：去掉 ```json ... ``` 包裹
                if s.startswith("```"):
                    s = s.split("```", 2)[1] if s.count("```") >= 2 else s
                    s = s.replace("json", "", 1).strip()

                try:
                    mutate_strategy = json.loads(s)
                except Exception as e:
                    raise ValueError(f"mutate_strategy is str but not valid JSON: {e}")
            elif not isinstance(mutate_strategy, dict):
                raise TypeError(f"mutate_strategy must be dict or JSON str, got {type(mutate_strategy)}")

        # 从 mutate_strategy 中提取所有的 mutation_plan
        plans = {}
        for k, v in mutate_strategy.items():
            if k.startswith("mutation_plan"):
                plans[k] = v  # v 就是这个 plan 的值（通常是 list）
        
        plan_idx = 0 
        for plan_name, plan_value in plans.items():

            mutate_prompt = open(os.path.join(PROMPT_DIR, "r2_complete_prompt.md"), "r").read()
            mutate_prompt = mutate_prompt.replace("{{SOURCE_CODE}}", source_code).replace("{{MUTATION_STRATEGY}}", str(plan_value))
            mutate_prompt = mutate_prompt.replace("{{DATA_FLOW}}", "\n".join(dataflow_str))

            banner_print("[+] Generating mutated variant code ...")
            response = openai_chat(mutate_prompt, temperature=0.1, model=model, custom_api_key=api_key)
            # 去掉<ANSWER> 标签
            if response.startswith("<ANSWER>"):
                response = response[len("<ANSWER>"):].strip()
            if response.endswith("</ANSWER>"):
                response = response[:-len("</ANSWER>")].strip()

            # 获取当前文件中策略个数，因为可能多次执行
            with open(os.path.join(VARIANT_CODE_DIR, model, cve_id, f"{src_code_idx}_variant_{var_idx}_{plan_idx}.php"), "w", encoding="utf-8") as f:
                f.write(response)

            # 找个位置保存变体
            banner_print(f"plan {plan_name} applied, variant saved to {os.path.join(VARIANT_CODE_DIR, model, cve_id, f'{src_code_idx}_variant_{var_idx}_{plan_idx}.php')}")
            plan_idx += 1
        banner_print("mutate complete")
        # print(response)

    return response


def variant_vuln_patch_complete(var_code_path, original_patch, model="gpt-5"):
    # 为每个变体生成补丁，这个补丁参考原始补丁实现

    pass