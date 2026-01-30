import copy
import json
import logging
import re
import os
import time
from typing import Union, List

import py2neo

from core.anchor_node import AnchorNode, BaseNode, get_specify_parent_node
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *

logger = logging.getLogger(__name__)


class AnchorNodeMatcher(object):
    def __init__(self, high_version_node: Union[AnchorNode, BaseNode],
                 high_version_analyzer: Neo4jEngine,
                 low_version_analyzer: Neo4jEngine,
                 high_version_prefix: str,
                 low_version_prefix: str):
        self.low_version_prefix = low_version_prefix
        self.high_version_prefix = high_version_prefix
        self.high_version_analyzer = high_version_analyzer
        self.low_version_analyzer = low_version_analyzer
        self.high_version_node = high_version_node
        self.node_type = None

    @staticmethod
    def __get_func_or_file_name(analyzer: Neo4jEngine, node: py2neo.Node):
        rt_value = ""
        top_node = analyzer.basic_step.get_node_itself(node[NODE_FUNCID])
        if top_node[NODE_TYPE] in {TYPE_METHOD, TYPE_FUNC_DECL}:
            rt_value = analyzer.code_step.get_node_code(top_node)
        elif top_node[NODE_TYPE] in {TYPE_CLOSURE}:
            rt_value = "anonymous_function"
        # 对 file 的处理
        elif top_node[NODE_TYPE] in {TYPE_TOPLEVEL}:
            if "_prepatch" in top_node[NODE_NAME]:
                rt_value = os.path.basename(top_node[NODE_NAME]).split("_prepatch")[0]
            elif "_postpatch" in top_node[NODE_NAME]:
                rt_value = os.path.basename(top_node[NODE_NAME]).split("_postpatch")[0]
            elif top_node[NODE_NAME].endswith(".php"):
                rt_value = os.path.basename(top_node[NODE_NAME])[:-4]
        assert rt_value != ""
        return rt_value
        
    def run(self, node_type=None) -> List[py2neo.Node] | str:
        start_time = time.time()
        self.node_type = node_type
        potential_anchors, reason = self.match_node()   # 这个 anchor 就是 postpatch 里的 node 了
        if potential_anchors is not None:
            potential_anchors = self.node_filter(potential_anchors)     # 这步很耗时，需要优化
            if potential_anchors.__len__() == 0:
                reason = f"NO FUNC {self.high_version_node.func_name}"
        end_time = time.time()
        print(f"AnchorNodeMatcher run time: {end_time - start_time} seconds")
        storage_sink_list = [{"id": i.node_id} for i in potential_anchors]
        if storage_sink_list:
            with open("temp_node_anchor", "w") as f:
                json.dump(obj=storage_sink_list, fp=f)
        return potential_anchors, reason

    def match_node(self) -> List[py2neo.Node] | str:
        self.low_version_file_name = self.high_version_node.file_name.replace(self.high_version_prefix,
                                                                      self.low_version_prefix)
        return self._match_low_version_potential_anchor()

    def _match_low_version_potential_anchor(self) -> List[py2neo.Node] | str:
        if self.low_version_file_name.endswith(".php"):
            query_file_name = os.path.basename(self.low_version_file_name)[:-4]  # 去掉 .php 后缀
        elif self.low_version_file_name.endswith("prepatch"):
            query_file_name = os.path.basename(self.low_version_file_name).split("_prepatch")[0]
        top_file_node = self.low_version_analyzer.fig_step.get_file_name_node(query_file_name)
        if top_file_node is None:
            return None, ""
        fileid = top_file_node[NODE_INDEX]
        anchor_node = self.high_version_node
        if {anchor_node.func_name} & {'include', 'include_once', 'require', 'require_once', 'eval'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_INCLUDE_OR_EVAL)
        elif {anchor_node.func_name} & {'echo'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_ECHO)
        elif {anchor_node.func_name} & {'print'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_PRINT)
        elif {anchor_node.func_name} & {'die', 'exit'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_EXIT)
        elif {anchor_node.func_name} & {'return'}:
            nodes = self.low_version_analyzer.match(fileid=fileid, type=TYPE_RETURN)
        else:
            nodes = []
            if "::" in anchor_node.func_name:
                func_name = anchor_node.func_name[anchor_node.func_name.index("::") + "::".__len__():]
            elif "->" in anchor_node.func_name:
                func_name = anchor_node.func_name[anchor_node.func_name.index("->") + "->".__len__():]
            else:
                func_name = anchor_node.func_name
            # _nodes = self.low_version_analyzer.match(fileid=fileid, code=func_name)
            _nodes = [i for i in self.low_version_analyzer.match("AST", ).where(code=func_name)]
            for _n in _nodes:      # 当patch 过后把这个删除了  这里 anchor 就失效了
                __n = get_specify_parent_node(self.low_version_analyzer, _n, FUNCTION_CALL_TYPES)
                if __n is not None:
                    nodes.append(__n)
        potential_anchors = []
        for node in nodes:
            cnt = self.low_version_analyzer.ast_step.get_function_arg_node_cnt(node)
            if cnt - 1 < max(self.high_version_node.param_loc):
                continue
            if self.node_type is not None:
                if self.node_type == node[NODE_TYPE]:
                    if self.node_type == TYPE_ECHO:
                        if self.low_version_analyzer. \
                                ast_step.get_function_arg_ith_node(node, 0)[NODE_TYPE] == TYPE_STRING:
                            continue
                    potential_anchors.append(node)
        if potential_anchors.__len__() == 0:
            return None, "NO FUNC " + self.high_version_node.func_name
        return potential_anchors, ""

    def node_filter(self, _potential_anchor_nodes):
        potential_anchor_nodes = []
        arg = sorted(
            self.high_version_analyzer.code_step.find_variables(
                self.high_version_analyzer.get_node_itself(self.high_version_node.node_id),
                target_type=VAR_TYPES_EXCLUDE_CONST_VAR))
        func_or_file_name = AnchorNodeMatcher.__get_func_or_file_name(
            self.high_version_analyzer,
            self.high_version_analyzer.get_node_itself(self.high_version_node.node_id))
        _args = map(lambda x: sorted(
            self.low_version_analyzer.code_step.find_variables(x,
                                                               target_type=VAR_TYPES_EXCLUDE_CONST_VAR)),
                    _potential_anchor_nodes)
        _func_or_file_name = map(lambda x: AnchorNodeMatcher.__get_func_or_file_name(self.low_version_analyzer, x),
                                 _potential_anchor_nodes)
        for _arg, _func_name, _potential_anchor_node in zip(_args, _func_or_file_name, _potential_anchor_nodes):
            if func_or_file_name == _func_name:
                if set(_arg).issubset(set(arg)) or set(arg).issubset(set(_arg)):
                    potential_anchor_nodes.append(_potential_anchor_node)
        return potential_anchor_nodes
