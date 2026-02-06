import re
# from difftools import parse_diff


blacklist = [
    "__must_hold"
]

def find_nearest_function_to_changes(lines, changed_line_indices):
    """
    
    
    Args:
        lines: diff
        changed_line_indices: +/-
    
    Returns:
        
    """
    if not changed_line_indices:
        return None
    
    # C
    function_patterns = [
        # C: return_type function_name(params)
        r'^[+-]?\s*(?:static\s+)?(?:inline\s+)?(?:const\s+)?(?:[a-zA-Z_][a-zA-Z0-9_*\s]*[\s*]+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{?',
        # : function_name(params)
        r'^[+-]?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{?',
        # 
        r'^[+-]?\s*(?:void|int|char|float|double|struct\s+\w+|[a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
    ]
    
    # 
    min_change_idx = min(changed_line_indices)
    
    # 
    for i in range(min_change_idx - 1, max(0, min_change_idx - 50), -1):
        line = lines[i]
        
        # 
        if not line.strip():
            continue
            
        # 
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue
            
        # diff
        if stripped.startswith('@@ ') or stripped.startswith('diff ') or stripped.startswith('index ') or stripped.startswith('--- ') or stripped.startswith('+++ '):
            continue
        
        # diff
        clean_line = line
        if line.startswith(('+', '-')):
            continue
        if line.startswith(('+', '-', ' ')):
            clean_line = line[1:]
        
        # 
        for pattern in function_patterns:
            match = re.search(pattern, clean_line)
            if match:
                func_name = match.group(1).strip()
                
                # C
                c_keywords = {'if', 'for', 'while', 'switch', 'return', 'static', 'void', 'int', 
                            'char', 'float', 'double', 'struct', 'union', 'enum', 'typedef',
                            'const', 'volatile', 'extern', 'inline', 'register', 'auto',
                            'goto', 'break', 'continue', 'case', 'default', 'sizeof'}
                
                if func_name and func_name not in c_keywords:
                    if clean_line.endswith(";"):
                        continue
                    if func_name in blacklist:
                        continue
                    # print(f"DEBUG:  '{func_name}'  {i}: {clean_line.strip()}")
                    return func_name
    
    return None

def extract_function_from_hunk_header(hunk_header):
    """
    hunk header
    : @@ -2766,7 +2766,7 @@ mrb_vm_exec(mrb_state *mrb, const struct RProc *proc, const mrb_code *pc)
    """
    #  @@ ... @@ 
    pattern = r'@@.*?@@\s*(.+)$'
    match = re.search(pattern, hunk_header)
    if match:
        context = match.group(1).strip()
        # print(f"DEBUG: hunk header context: {context}")
        
        # 
        #  function_name(params) 
        func_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', context)
        if func_match:
            func_name = func_match.group(1)
            # print(f"DEBUG: hunk header: {func_name}")
            return func_name
    
    return None

def parse_diff(diff_content):
    """
    diff
    """
    result = {"functions": [], "header_functions": [], "added": [], "deleted": []}
    
    lines = diff_content.strip().split('\n')
    old_line_num = 0
    new_line_num = 0
    
    # 
    changed_line_indices = []
    
    # hunk header
    hunk_pattern = r'@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@.*'
    
    i = 0
    current_hunk_start = None
    current_hunk_changes = []  # hunk
    
    while i < len(lines):
        line = lines[i]
        
        # 
        if line.startswith(('diff --git', 'index', '---', '+++')):
            i += 1
            continue
        
        # hunk header
        hunk_match = re.match(hunk_pattern, line)
        if hunk_match:
            # hunk
            if current_hunk_start is not None and current_hunk_changes:
                # print(f"DEBUG: hunk: {current_hunk_changes}")
                func_name = find_nearest_function_to_changes(lines, current_hunk_changes)
                if func_name and func_name not in result["functions"]:
                    result["functions"].append(func_name)
            
            # hunk header
            hunk_func = extract_function_from_hunk_header(line)
            if hunk_func and hunk_func not in result["header_functions"]:
                result["header_functions"].append(hunk_func)
            
            # hunk
            current_hunk_start = i
            current_hunk_changes = []
            
            old_start = int(hunk_match.group(1))
            new_start = int(hunk_match.group(3))
            old_line_num = old_start
            new_line_num = new_start
            
            i += 1
            continue
        
        # 
        if line.startswith('-'):
            # 
            content = line[1:]
            content = re.sub(r'^\*\s*', '', content)
            content = re.sub(r'\s*\*$', '', content)
            result["deleted"].append([old_line_num, content.strip()])
            old_line_num += 1
            current_hunk_changes.append(i)
            changed_line_indices.append(i)
            
        elif line.startswith('+'):
            # 
            content = line[1:]
            content = re.sub(r'^\*\s*', '', content)
            content = re.sub(r'\s*\*$', '', content)
            result["added"].append([new_line_num, content.strip()])
            new_line_num += 1
            current_hunk_changes.append(i)
            changed_line_indices.append(i)
            
        elif line.startswith(' '):
            # 
            old_line_num += 1
            new_line_num += 1
        
        i += 1
    
    # hunk
    if current_hunk_start is not None and current_hunk_changes:
        # print(f"DEBUG: hunk: {current_hunk_changes}")
        func_name = find_nearest_function_to_changes(lines, current_hunk_changes)
        if func_name and func_name not in result["functions"]:
            result["functions"].append(func_name)
    
    # 
    if not result["functions"] and changed_line_indices:
        # print(f"DEBUG: : {changed_line_indices}")
        func_name = find_nearest_function_to_changes(lines, changed_line_indices)
        if func_name:
            result["functions"].append(func_name)
    
    result["added"] = sorted(result["added"], key=lambda x: x[0])
    result["deleted"] = sorted(result["deleted"], key=lambda x: x[0])
    
    return result

# 
def test():
    diff_content = """
diff --git a/drivers/net/slip/slip.c b/drivers/net/slip/slip.c
index 88396ff99f03f7..6865d32270e5d0 100644
--- a/drivers/net/slip/slip.c
+++ b/drivers/net/slip/slip.c
@@ -469,7 +469,7 @@ static void sl_tx_timeout(struct net_device *dev, unsigned int txqueue)
        spin_lock(&sl->lock);

        if (netif_queue_stopped(dev)) {
-               if (!netif_running(dev))
+               if (!netif_running(dev) || !sl->tty)
                        goto out;

                /* May be we must check transmitter timeout here ? */
"""
    
    result = parse_diff(diff_content)
    print("\n===  ===")
    print(":", result["functions"])
    print("header:", result["header_functions"])
    print(":", result["added"])
    print(":", result["deleted"])
    print("-" * 150)


    diff_content = """diff --git a/src/isomedia/box_code_3gpp.c b/src/isomedia/box_code_3gpp.c
index 3f9ff05692..928a5575f2 100644
--- a/src/isomedia/box_code_3gpp.c
+++ b/src/isomedia/box_code_3gpp.c
@@ -1128,20 +1128,12 @@ void diST_box_del(GF_Box *s)
 
 GF_Err diST_box_read(GF_Box *s, GF_BitStream *bs)
 {
-	u32 i;
-	char str[1024];
 	GF_DIMSScriptTypesBox *p = (GF_DIMSScriptTypesBox *)s;
 
-	i=0;
-	str[0]=0;
-	while (1) {
-		str[i] = gf_bs_read_u8(bs);
-		if (!str[i]) break;
-		i++;
-	}
-	ISOM_DECREASE_SIZE(p, i);
-
-	p->content_script_types = gf_strdup(str);
+	p->content_script_types = gf_malloc(sizeof(char) * (s->size+1));
+	if (!p->content_script_types) return GF_OUT_OF_MEM;
+	gf_bs_read_data(bs, p->content_script_types, s->size);
+	p->content_script_types[s->size] = 0;
 	return GF_OK;
 }
"""
    
    result = parse_diff(diff_content)
    print("\n===  ===")
    print(":", result["functions"])
    print("header:", result["header_functions"])
    print(":", result["added"])
    print(":", result["deleted"])
    print("-" * 150)


    diff_content = """diff --git a/fs/io_uring.c b/fs/io_uring.c
index fafd1ca4780b6a..659f8ecba5b790 100644
--- a/fs/io_uring.c
+++ b/fs/io_uring.c
@@ -1736,12 +1736,11 @@ static __cold void io_flush_timeouts(struct io_ring_ctx *ctx)
 	__must_hold(&ctx->completion_lock)
 {
 	u32 seq = ctx->cached_cq_tail - atomic_read(&ctx->cq_timeouts);
+	struct io_kiocb *req, *tmp;
 
 	spin_lock_irq(&ctx->timeout_lock);
-	while (!list_empty(&ctx->timeout_list)) {
+	list_for_each_entry_safe(req, tmp, &ctx->timeout_list, timeout.list) {
 		u32 events_needed, events_got;
-		struct io_kiocb *req = list_first_entry(&ctx->timeout_list,
-						struct io_kiocb, timeout.list);
 
 		if (io_is_timeout_noseq(req))
 			break;
@@ -1758,7 +1757,6 @@ static __cold void io_flush_timeouts(struct io_ring_ctx *ctx)
 		if (events_got < events_needed)
 			break;
 
-		list_del_init(&req->timeout.list);
 		io_kill_timeout(req, 0);
 	}
 	ctx->cq_last_tm_flush = seq;
@@ -6628,6 +6626,7 @@ static int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe,
 	if (data->ts.tv_sec < 0 || data->ts.tv_nsec < 0)
 		return -EINVAL;
 
+	INIT_LIST_HEAD(&req->timeout.list);
 	data->mode = io_translate_timeout_mode(flags);
 	hrtimer_init(&data->timer, io_timeout_get_clock(data), data->mode);
"""
    
    result = parse_diff(diff_content)
    print("\n===  ===")
    print(":", result["functions"])
    print("header:", result["header_functions"])
    print(":", result["added"])
    print(":", result["deleted"])





def main():
    pass


if __name__ == "__main__":
    main()