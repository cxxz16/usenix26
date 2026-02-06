from tree_sitter import Node, Language, Parser
from os.path import join
import rich
import ipdb

TS_PHP_METHOD = "(method_declaration) @method"
LANGUAGE = Language("./core/slice_diff_all/build/my-languages.so", "php")
parser = Parser()
parser.set_language(LANGUAGE)

# pre_file_path = join(cve_8637_code, "prepatch", "code", "tree.class_prepatch.php")
pre_file_path = "./multi_agent/VVG/test_ph.php"
# code = open(pre_file_path, "r", encoding="utf-8").read()
code = """<?php
// 
class UserManager {
    private $username;
    private $password;
    
    /* 
     * 
     * 
     */
    public function __construct($user, $pass) {
        $this->username = $user;
        $this->password = $pass;
    }
    
    // 
    public function getUsername() {
        return $this->username;
    }
    
    public function validateUser($inputUser, $inputPass) {
        if ($inputUser === $this->username && $inputPass === $this->password) {
            return true;
        }
        return false;
    }
}

class DatabaseManager {
    private $connection;
    
    public function connect($host, $dbname) {
        $this->connection = new PDO("mysql:host=$host;dbname=$dbname");
        return $this->connection;
    }
}

$manager = new UserManager("admin", "secret");
$result = $manager->validateUser("test", "pass");
?>"""
tree = parser.parse(bytes(code, "utf-8"))
root_node = tree.root_node
debug = True

def query(query_str: str):
    query = LANGUAGE.query(query_str)
    captures = query.captures(root_node)
    return captures

def print_tree(node, indent=0):
    print('    ' * indent + f"{node.type} [{node.start_point} - {node.end_point}]")
    for child in node.children:
        print_tree(child, indent + 1)

rich.inspect(root_node, all=True)
ipdb.set_trace(context=5)
# print_tree(root_node)

# def extract_assignment_vars(node):
#     results = []
#     if node.type == "assignment_expression":
#         left = node.child_by_field_name("left")
#         if left.type == "variable_name":
#             results.append(left.text.decode("utf-8"))
#     for child in node.children:
#         results.extend(extract_assignment_vars(child))
#     return results

# vars_assigned = extract_assignment_vars(root_node)
# print("", vars_assigned)

# query_method = TS_PHP_METHOD
# for method_node in query(query_method):
#     if debug:
#         rich.inspect(method_node, all=True)
#         ipdb.set_trace(context=5)
#         print_tree(method_node[0])
#         exec("debug=False")
#     print("bp") 

