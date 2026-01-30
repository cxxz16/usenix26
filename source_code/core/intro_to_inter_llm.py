from core.chat import openai_chat


prompt = """
你是资深的程序分析与软件开发专家，精通代码审计与 Web 应用开发，尤其擅长 PHP 相关任务。现在给出若干跨越多个函数调用的代码切片 —— 这些切片描述了跨过程（inter-procedural）的污点传播路径：外部输入（source）未经充分清理，直接或通过参数/返回值传播到敏感调用（sink）。

你的任务是：**将这些跨过程的代码切片整合为一个过程内（intra-procedural）的、语义等价的完整 PHP 函数/文件**，保证污点数据流清晰可见且保持原有语义，不修复漏洞，只做最小化补全以保证语法正确并能独立阅读。

注意要求（严格遵守）：
1. **不得修复或消除漏洞。** 必须保留完整的污点数据流（即 source 到 sink 的路径及其传播方式），不要改变数据的敏感性或引入过滤/转义逻辑。
2. **保持原语义。** 对被整合的代码行为、参数传递与返回值语义不得改变；只能做必要的重构以把跨函数调用“内联”成单一过程内的代码流。
3. **仅在与函数调用、参数或返回值相关的地方进行必要改动。** 其他不涉调用逻辑的代码段不要修改。
4. **最小化补全缺失代码。** 如果输入切片缺少变量声明、简单的辅助语句或上下文片段，仅补全最小必要部分以使输出成为可解析、独立的 PHP 文件；补全应尽量保守且与上下文一致。
5. **输出必须是完整且无语法错误的 PHP 文件**：包含 `<?php` 起始标记、函数定义与结束符号（若需要函数的话），可被 PHP 解析器语法检查通过。
6. **命名与注释保留/清晰化**：尽可能保留原有变量名与注释；如有必要可以新增辅助变量或占位符。
7. **输出格式** 固定为下列形式（严格遵守）：

# Input
source函数：
{source_api}
sink 函数：
{sink_api}
code slices:
{code_slices}

# Output
<ANSWER>
your answer.
</ANSWER>
"""

# def inter_to_intra_chat(source_api, sink_api, code_slices, save_dir, sp_idx, ps_idx):
#     prompt = f"""
#     You are a senior expert in program analysis and software development, highly skilled in code auditing and web application development, especially proficient in PHP-related tasks.  
#     You are given several code slices that span across multiple function calls — these slices represent **inter-procedural taint propagation paths**, where external input (source) is not properly sanitized and is directly or indirectly passed through parameters or return values into sensitive function calls (sink).

#     Your task is to **merge these inter-procedural code slices into a single intra-procedural, semantically equivalent, and complete PHP function/file**, ensuring that the taint data flow remains clear and the original semantics are preserved.  
#     You should not fix any vulnerabilities; instead, make minimal necessary completions so that the resulting code is syntactically correct and self-contained.

#     Strict requirements:
#     1. **Do not fix or remove vulnerabilities.** You must preserve the complete taint data flow (i.e., from source to sink and all propagation steps). Do not change the sensitivity of data or introduce sanitization/escaping logic.
#     2. **Preserve original semantics.** Do not alter the behavior of the integrated code, its parameter passing, or return value semantics. Only perform the necessary restructuring to inline cross-function calls into a single intra-procedural flow.
#     3. **Modify only where function calls, parameters, or return values are involved.** Do not change unrelated code segments.
#     4. **Minimize code completion.** If the given slices lack variable declarations, helper statements, or context, only add the minimal necessary code to make the output a valid, self-contained PHP file. Completions must be conservative and consistent with the surrounding context.
#     5. **The output must be a complete, syntax-error-free PHP file** — it should include the `<?php` opening tag, function definitions and closing braces (if needed), and must be parsable by a PHP interpreter.
#     6. **Preserve and clarify naming and comments.** Retain original variable names and comments wherever possible. You may add helper variables or placeholders if necessary.
#     7. **The output format must strictly follow the structure below.** The synthesized code must be enclosed within the <ANSWER> tags, and no other content should be output.

#     # Input
#     source function:
#     {source_api}
#     sink function:
#     {sink_api}
#     code slices:
#     {code_slices}

#     # Output
#     <ANSWER>
#     your answer.
#     </ANSWER>
#     """

def inter_to_intra_chat(source_api, sink_api, code_slices, save_dir, sp_idx, ps_idx):
    # You are an experienced PHP developer.
    # You are given several PHP code snippets (code slices) that come from different functions, forming a call chain from a source function to a sink function.

    # Please combine all these code slices according to their function call order into one single, semantically equivalent piece of PHP code.
    # The result should include all logic in a single function or directly within a PHP file (without functions if possible).
    # Ensure the combined code is **logically coherent** and **syntactically correct PHP code** that can be executed without syntax errors.

    # Note:
    # 1. Do not fix, modify, or remove any vulnerabilities you find in the code. Keep all potential security issues exactly as they are.
    # 2. Do not change any logic except where necessary to adapt function calls into the merged single-function (or single-file) structure.
    # 3. When encountering a function that is in the source function or sink function list, there is no need to inline the function call — it can be used directly.
    prompt = f"""
According to the function call logic, merge the implementations of the following functions into a single function while keeping the semantics unchanged.
For functions listed in the source and sink lists, do not expand their implementations — just keep their function calls as they are.
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


    resp = openai_chat(
        prompt,
        model="gpt-5-2025-08-07"
    )

    resp = resp.split("<ANSWER>")[1].split("</ANSWER>")[0].strip()

    if resp.startswith("<?php") is False:
        resp = "<?php\n" + resp
    with open(f"{save_dir}/{sp_idx}_{ps_idx}.php", "w") as f:
        f.write(resp)

    return resp


def source_sink_slice_fix_and_merge(source_api, sink_api, code_slices, save_dir, ss_idx, model="gpt-5"):
    # 你是一个富有经验的软件开发工程师，擅长php语言。我将给你几段代码，这些代码段可能在语法层面存在缺失，现在需要你在不改变代码原意的要求下进行最小化的修复。

    # 这些代码片段可能来自于不同的函数，这些代码段之间存在函数调用关系。请你阅读并理解这些代码片段，同时参考在`Code slices` 开头提供的 `Call Relations` ，识别并确定这些代码段之间的调用关系。

    # 根据调用关系，现在需要你做：
    # 如果在函数调用点处涉及的函数实现在给定代码段中不存在，则保持他在调用点处的代码。不需要改变。
    # 如果在函数调用点处涉及的函数在`source function `列表 和 `sink function `列表中，则保持他在调用点处的代码。不需要改变。
    # 否则，根据调用关系将不同函数中的代码段整合到一个函数中。同时保持语义不变。基本的思想就是将被调用函数内联到主调用函数中。同时修正参数和返回值的关系。

    # 最后对合并后的新代码做语法层面的最小化修复，不要修改任何函数语义。
    # 对于函数注释为 // Scope: Global Scope 的代码段，他是属于上方file的全局代码。


    # You are an experienced PHP developer.
    # You are given several PHP code snippets (code slices) that come from different functions, forming a call chain from a source function to a sink function.

    # Please combine all these code slices according to their function call order into one single, semantically equivalent piece of PHP code.
    # The result should include all logic in a single function or directly within a PHP file (without functions if possible).
    # Ensure the combined code is **logically coherent** and **syntactically correct PHP code** that can be executed without syntax errors.

    # Note:
    # 1. Do not fix, modify, or remove any vulnerabilities you find in the code. Keep all potential security issues exactly as they are.
    # 2. Do not change any logic except where necessary to adapt function calls into the merged single-function (or single-file) structure.
    # 3. When encountering a function that is in the source function or sink function list, there is no need to inline the function call — it can be used directly.
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

    resp = openai_chat(
        prompt,
        model=model
    )

    resp = resp.split("<ANSWER>")[1].split("</ANSWER>")[0].strip()

    if resp.startswith("<?php") is False:
        resp = "<?php\n" + resp
    with open(f"{save_dir}/{ss_idx}.php", "w") as f:
        f.write(resp)

    return resp


def source_sink_slice_fix_only(code_slices, save_dir, ss_idx, model="gpt-5-2025-08-07"):
    # You are an experienced PHP developer.
    # You are given several PHP code snippets (code slices) that come from different functions, forming a call chain from a source function to a sink function.

    # Please combine all these code slices according to their function call order into one single, semantically equivalent piece of PHP code.
    # The result should include all logic in a single function or directly within a PHP file (without functions if possible).
    # Ensure the combined code is **logically coherent** and **syntactically correct PHP code** that can be executed without syntax errors.

    # Note:
    # 1. Do not fix, modify, or remove any vulnerabilities you find in the code. Keep all potential security issues exactly as they are.
    # 2. Do not change any logic except where necessary to adapt function calls into the merged single-function (or single-file) structure.
    # 3. When encountering a function that is in the source function or sink function list, there is no need to inline the function call — it can be used directly.
    prompt = f"""
You are an experienced software development engineer proficient in PHP. I will give you a piece of code that may have syntactic flaws. You need to make minimal modifications to the code to ensure that it is syntactically correct without changing its original meaning. Additionally, do not write it in a class-based form; convert it into a standalone function implementation.
### Note 1: Do not change any of the original meanings of the code; only fix the syntax.
### Note 2: You must remove all visibility modifiers (public, protected, private, static) because they are only valid inside classes.
### Note 3: Additionally, for control-flow structures such as if/else, try/catch, and switch/case, you must ensure their syntax is complete. You do not need to fill in the internal logic, but the structure itself must be syntactically valid — for example, if there is a try block, you must also add a corresponding catch block.

### Note 4: If the source code snippet contains many class members or class methods (identified by keywords such as `self`), convert these references into regular local variables inside the function. Do not keep any class-related markers.

### Note 5: Please double-check for any syntax issues. Make sure the final output is a complete PHP file that can be parsed by a PHP interpreter without any syntax errors.
    # Input
    code slices:
    {code_slices}

    # Output
    <ANSWER>
    your answer.
    </ANSWER>
    """


    resp = openai_chat(
        prompt,
        model=model
    )

    resp = resp.split("<ANSWER>")[1].split("</ANSWER>")[0].strip()

    if resp.startswith("<?php") is False:
        resp = "<?php\n" + resp
    with open(f"{save_dir}/{ss_idx}.php", "w") as f:
        f.write(resp)

    return resp


def inter_to_intra_chat_ss(source_api, code_slices, save_dir, sp_idx, node_id):
    # You are an experienced PHP developer.
    # You are given several PHP code snippets (code slices) that come from different functions, forming a call chain from a source function to a sink function.

    # Please combine all these code slices according to their function call order into one single, semantically equivalent piece of PHP code.
    # The result should include all logic in a single function or directly within a PHP file (without functions if possible).
    # Ensure the combined code is **logically coherent** and **syntactically correct PHP code** that can be executed without syntax errors.

    # Note:
    # 1. Do not fix, modify, or remove any vulnerabilities you find in the code. Keep all potential security issues exactly as they are.
    # 2. Do not change any logic except where necessary to adapt function calls into the merged single-function (or single-file) structure.
    # 3. When encountering a function that is in the source function or sink function list, there is no need to inline the function call — it can be used directly.
    prompt = f"""
According to the function call logic, merge the implementations of the following functions into a single function while keeping the semantics unchanged.
For functions listed in the source and sink lists, do not expand their implementations — just keep their function calls as they are.
    # Input
    source function:
    {source_api}
    code slices:
    {code_slices}

    # Output
    <ANSWER>
    your answer.
    </ANSWER>
    """


    resp = openai_chat(
        prompt,
        model="gpt-5-2025-08-07"
    )

    resp = resp.split("<ANSWER>")[1].split("</ANSWER>")[0].strip()

    if resp.startswith("<?php") is False:
        resp = "<?php\n" + resp
    with open(f"{save_dir}/sink_{node_id}_{sp_idx}.php", "w") as f:
        f.write(resp)

    return resp