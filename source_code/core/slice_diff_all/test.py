import re

def parse_key_value_pairs(text):
    # 提取方括号内容
    match = re.search(r'\[(.*)\]', text)
    if not match:
        return {}
    
    content = match.group(1)
    bracket_start = match.start(1)  # 方括号内容在原文中的起始位置
    pairs = {}
    
    # 找到所有可能的键值对分隔符（空格+键名+等号）
    # 键名通常是：空格后面跟着字母开头的单词，然后是等号
    # 也包括开头的 label
    key_pattern = r'(?:^|\s)([A-Z_][A-Z0-9_]*)\s*='
    key_matches = list(re.finditer(key_pattern, content))
    
    if not key_matches:
        return {}
    
    for i, key_match in enumerate(key_matches):
        key = key_match.group(1)
        eq_pos = key_match.end()  # 等号后的位置
        
        # 找值的开始位置（跳过等号后的空格）
        val_start = eq_pos
        while val_start < len(content) and content[val_start] == ' ':
            val_start += 1
        
        # 找值的结束位置
        if i < len(key_matches) - 1:  # 不是最后一个键值对
            # 下一个键值对的开始位置（包括前导空格）
            next_match_start = key_matches[i + 1].start()
            val_end = next_match_start
        else:  # 最后一个键值对
            val_end = len(content)
        
        # 记录在整个原始字符串中的位置
        global_val_start = bracket_start + val_start
        global_val_end = bracket_start + val_end
        
        value = content[val_start:val_end].rstrip()  # 去掉末尾空格
        
        # 去掉值两端的引号（如果有的话）
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        
        pairs[key] = (value, (global_val_start, global_val_end))
    
    return pairs

# 测试
text1 = '30064771437[label=CALL ARGUMENT_INDEX="2" CODE="$t[\"conditions\"]($this->newExpr(),$this)" DISPATCH_TYPE="STATIC_DISPATCH" DYNAMIC_TYPE_HINT_FULL_NAME="Cake\Database\Query->$t["conditions"]" LINE_NUMBER="732" METHOD_FULL_NAME="Cake\Database\Query->$t["conditions"]" NAME="$t["conditions"]" ORDER="2" SIGNATURE="<unresolvedSignature>(2)" TYPE_FULL_NAME="ANY"]'

text2 = '30064772468[label=CALL ARGUMENT_INDEX="-1" CODE="\"$tmp84[\"Content-Disposition\"] = sprintf(\"attachment;; filename=\"%s\"",$asset->getFilename())" DISPATCH_TYPE="STATIC_DISPATCH" LINE_NUMBER="1183" METHOD_FULL_NAME="<operator>.assignment" NAME="<operator>.assignment" ORDER="3" SIGNATURE="" TYPE_FULL_NAME="ANY"]'

print("测试1:")
result1 = parse_key_value_pairs(text1)
for k, (v, pos) in result1.items():
    print(f'{k} = {v} (位置: {pos[0]}-{pos[1]})')

print("\n测试2:")
result2 = parse_key_value_pairs(text2)
for k, (v, pos) in result2.items():
    print(f'{k} = {v} (位置: {pos[0]}-{pos[1]})')