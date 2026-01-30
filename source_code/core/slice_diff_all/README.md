# 文件夹说明
这个是所有和 code slice、处理 diff 相关的代码，后续所有的 slice 代码和处理 diff 代码都在这个文件夹内维护和开发


## Dependencies

- `Joern` - 2.0.446
- `Java` - openjdk 11.0.2 2019-01-15 
- `tree-sitter` - 0.21.0
- `tree-sitter-c` - 0.23.4
- `tree-sitter-php` - 0.23.11


## file description
- `variable_slice.py` - 以关键变量为基准做切片
- `code_process_symbol.py` - joern 导出的 cpg.dot 中有些字段不符合 nx 的 read_dot 规范，预处理。" -> \"
- `patch_process.py` - 识别 github 给出的 diff 文件中受影响的函数
- `code_process_line.py` - 将源代码中的多行代码转为一行