import os
import py2neo
from core.neo4j_engine.const import *
from core.neo4j_engine import Neo4jEngine

def get_method_call_name(analyzer: Neo4jEngine, node: py2neo.Node) -> str:

    def get_method_var_call_name(node: py2neo.Node) -> str:
        #  $this->method()  
        method_var_node = analyzer.find_ast_child_nodes(node, include_type={TYPE_VAR})
        if method_var_node:
            method_var_node = method_var_node[0]
            method_var_name_nodes = analyzer.filter_ast_child_nodes(method_var_node, node_type_filter={TYPE_STRING})
            method_var_name_nodes = list(sorted(method_var_name_nodes, key=lambda x: x[NODE_INDEX]))
            method_name = ""
            if method_var_name_nodes:
                method_name += "$"   
                method_name += "->".join([n['code'] for n in method_var_name_nodes])
            method_name_node = analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
            if method_name_node:
                method_name_node = method_name_node[0]
                method_name += "->" + method_name_node['code']
            return method_name
        return None


    method_call_name = None
    node_type = node[NODE_TYPE]
    match node_type:
        case 'AST_METHOD_CALL':
            prop_node = analyzer.find_ast_child_nodes(node, include_type={TYPE_PROP})
            if prop_node:
                prop_node = prop_node[0]
                prop_str_nodes = analyzer.filter_ast_child_nodes(prop_node, node_type_filter={TYPE_STRING})
                prop_str_nodes = list(sorted(prop_str_nodes, key=lambda x: x[NODE_INDEX]))
                prop_name = "$"
                if prop_str_nodes:
                    prop_name += "->".join([n['code'] for n in prop_str_nodes]) 
                method_name_nodes = analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                if method_name_nodes:
                    method_name_node = method_name_nodes[0]
                    prop_name += "->" + method_name_node['code']
                method_call_name = prop_name
            else:
                #  var call
                method_call_name = get_method_var_call_name(node)
                if method_call_name is None:
                    method_submethod_node = analyzer.find_ast_child_nodes(node, include_type={TYPE_METHOD_CALL})
                    if method_submethod_node:
                        parent_method_node = method_submethod_node[0]
                        parent_method_name = get_method_var_call_name(parent_method_node)

                        if parent_method_name is not None:
                            method_name_nodes = analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                            if method_name_nodes:
                                method_name_node = method_name_nodes[0]
                                parent_method_name += "()->" + method_name_node['code']
                                method_call_name = parent_method_name


            if method_call_name is None:
                # 
                # $this->di['db']->getCell($sql , $values);   $di['request']->getClientAddress(), 
                dim_node = analyzer.find_ast_child_nodes(node, include_type={TYPE_DIM})
                dim_node_method_call_name = analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                try:
                    if dim_node:
                        dim_node = dim_node[0]
                        dim_name_nodes = analyzer.find_ast_child_nodes(dim_node, include_type={TYPE_STRING})
                        dim_prop_node = analyzer.find_ast_child_nodes(dim_node, include_type={TYPE_PROP})
                        if dim_prop_node:
                            method_name = "$"
                            dim_prop_node = dim_prop_node[0]
                            dim_prop_var_node = analyzer.find_ast_child_nodes(dim_prop_node, include_type={TYPE_VAR})
                            dim_prop_var_name_node = analyzer.find_ast_child_nodes(dim_prop_var_node[0], include_type={TYPE_STRING})

                            if dim_prop_var_name_node:
                                method_name += dim_prop_var_name_node[0]['code']

                            dim_prop_name_node = analyzer.find_ast_child_nodes(dim_prop_node, include_type={TYPE_STRING})
                            if dim_prop_name_node:
                                method_name += "->" + dim_prop_name_node[0]['code']
                                method_name += "['" + dim_name_nodes[0]['code'] + "']" 
                                method_name += "->" + dim_node_method_call_name[0]['code']
                                method_call_name = method_name
                except Exception as e:
                    method_call_name = None
                    pass

            if method_call_name is None:
                #  code
                method_call_name = analyzer.code_step.get_node_code(node)

        case 'AST_STATIC_CALL':
            name_node = analyzer.find_ast_child_nodes(node, include_type={TYPE_NAME})
            if name_node:
                name_node = name_node[0]
                static_name_node = analyzer.find_ast_child_nodes(name_node, include_type={TYPE_STRING})
                static_name = ""
                if static_name_node:
                    static_name_node = static_name_node[0]
                    static_name += static_name_node['code']
                static_method_name = analyzer.find_ast_child_nodes(node, include_type={TYPE_STRING})
                if static_method_name:
                    static_method_name = static_method_name[0]
                    static_name += "::" + static_method_name['code']
                method_call_name = static_name

    if method_call_name is None:
        #  code
        method_call_name = analyzer.code_step.get_node_code(node)
    return method_call_name


