from core.chat import openai_chat


prompt = """
 Web  PHP  —— inter-proceduralsource/sink

**intra-procedural PHP /**


1. ****  source  sink /
2. **** “”
3. **** 
4. ****  PHP 
5. ** PHP ** `<?php`  PHP 
6. **/**
7. **** 

# Input
source
{source_api}
sink 
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
    # php

    # `Code slices`  `Call Relations` 

    # 
    # 
    # `source function `  `sink function `
    # 

    # 
    #  // Scope: Global Scope file


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