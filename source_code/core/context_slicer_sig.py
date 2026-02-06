import logging
import pickle
from platform import node
import json
import os.path
from typing import Dict, List, Set, Tuple, Union
import networkx as nx
import py2neo
import matplotlib.pyplot as plt
from typing import List
from config.path import STORAGE_PATH
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.modified_line import ModifiedLine
from core.anchor_node import AnchorNode
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.ast2code import Ast2CodeFactory
from core.chat import openai_chat
logger = logging.getLogger(__name__)

COMMON_NODE_TYPES = [
        TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL,
        TYPE_NEW,
        TYPE_INCLUDE_OR_EVAL,
        TYPE_ECHO, TYPE_PRINT, TYPE_EXIT
]

class ContextSlicerSig(object):
    def __init__(self, anchor_node: AnchorNode, analyzer: Neo4jEngine, commit_id=None, cve_id=None, custom_sources: set = None):
        self.analyzer = analyzer
        self.anchor_node = anchor_node
        self.commit_id = commit_id if commit_id else 'in_detection'
        self.anchor_node_ast = None
        self.anchor_node_root = None
        self.far_node = None
        self.pdg_digraph = nx.DiGraph()
        self.sources = set()
        self.custom_sources = custom_sources if custom_sources is not None else set()
        self.taint_param = set()
        self.cve_id = cve_id if cve_id else 'in_detection'
        self.__backup_anchor_node_id = -1
        self.potential_source_funcname = set()

        self.max_callee_direction_depth = 1
        self.max_caller_direction_level = 1

    def clear_cache(self):
        self.anchor_node_ast = None
        self.anchor_node_root = None
        self.far_node = None
        self.pdg_digraph = nx.DiGraph()
        self.sources = set()
        self.taint_param = set()

    def load_backward_paths(self):
        filepath = os.path.join(STORAGE_PATH, 'cve_source_finder', f'all_paths_{self.cve_id}_{self.commit_id}.pkl')
        if not os.path.exists(filepath):
            return False
        with open(filepath, 'rb') as f:
            self.backward_call_paths = pickle.load(f)
        if self.backward_call_paths is not None:
            return True
        else:
            return False
        
    def run(self):
        self.context_series = list()
        self.do_backward_slice()
        self.do_forward_path_exploration()
        self.anchor_node.node_id = self.__backup_anchor_node_id
        # 

        save_pdg_graph(self.pdg_digraph, "pdg_graph.png")
        self.dataflow_str_list = print_pdg_paths(self.pdg_digraph)
        return self.context_series

    def do_backward_slice(self):
        self.__backup_anchor_node_id = self.anchor_node.node_id

        taint_param = set()
        if self.anchor_node_ast is None:
            self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
        if self.anchor_node_root is None:
            self.anchor_node_root = self.analyzer.ast_step.get_root_node(self.anchor_node_ast)
        self._do_backward_slice(self.anchor_node_ast, pdg_parent=None, id_threshold=self.anchor_node_ast[NODE_INDEX],
                                taint_param=taint_param)
        self.far_node = min(self.pdg_digraph.nodes.keys())  #  node
        self.taint_param = taint_param

    def _do_backward_slice(self, node, pdg_parent=None, id_threshold=0xff, taint_param=None):
        if node is None:
            return None
        if node[NODE_INDEX] > id_threshold:
            return None
        
        if not self.analyzer.cfg_step.has_cfg(node):
            node = self.analyzer.ast_step.get_root_node(node)
            if node[NODE_TYPE] in {TYPE_IF, TYPE_IF_ELEM, TYPE_WHILE, TYPE_DO_WHILE}:
                node = self.analyzer.get_control_node_condition(node)

        self.pdg_digraph.add_node(
                node[NODE_INDEX], add_rels="PDG", root_node_id=node[NODE_INDEX], lineno=node[NODE_LINENO],
        )
        if self.analyzer.ast_step.find_sources(node, max_depth=15) or self.analyzer.ast_step.find_custom_sources(node, self.custom_sources):
            self.sources.add(node[NODE_INDEX])  #  nodefind_source childnode  assign assign 
        
        if pdg_parent is not None:
            assert taint_param is not None
            if self.pdg_digraph.has_edge(node[NODE_INDEX], pdg_parent[NODE_INDEX]):
                return
            else:
                self.pdg_digraph.add_edge(
                    node[NODE_INDEX], pdg_parent[NODE_INDEX], add_rels='PDG', taint_param=taint_param
                )
        
        #  node 
        def_nodes = self.analyzer.pdg_step.find_def_nodes(node)
        if node in def_nodes:
            def_nodes.pop(def_nodes.index(node))
        
        for def_node in def_nodes:
            if def_node is None or def_node[NODE_INDEX] > id_threshold: continue
            var = self.analyzer.neo4j_graph.relationships.match([def_node, node],
                                                                r_type=DATA_FLOW_EDGE).first()['var']
            taint_param = '$' + var
            self._do_backward_slice(def_node, pdg_parent=node, id_threshold=def_node[NODE_INDEX], 
                                taint_param=taint_param)

    # add:  source 
    def do_forward_path_exploration(self):
        potential_condition_nodes = [i for i, in self.analyzer.run(
            "MATCH (A:AST) - [:PARENT_OF] -> (B:AST) WHERE A.type='AST_IF_ELEM' AND B.childnum=0 " + \
            f"AND B.type <> 'NULL' AND {self.far_node - 100} <= B.id AND B.id <= {self.far_node} RETURN B"
        )]      #  far  check check  far_node  far_node  sink_node 
        condition_ids = set()
        for node in potential_condition_nodes:
            parent_node = self.analyzer.get_ast_parent_node(node)
            low_bound, high_bound = self.analyzer.range_step.get_condition_range(parent_node)
            if low_bound <= self.far_node and self.far_node <= high_bound and \
                    (self.analyzer.ast_step.find_sources(node) or self.analyzer.ast_step.find_custom_sources(node, self.custom_sources)):  #  check  global var condition  global  condition_ids check 
                condition_ids.add(node[NODE_INDEX])
        
        far_node_ast = self.analyzer.get_node_itself(self.far_node)

        if self.anchor_node_root[NODE_INDEX] == far_node_ast[NODE_INDEX]:
            self.context_series.append(([self.anchor_node.node_id], sorted(condition_ids)))
            return

        self._do_forward_path_exploration(node=far_node_ast, cfg_pdg_path=set(), path_conditions=condition_ids,  
                                          threshold=[far_node_ast[NODE_INDEX], self.anchor_node_ast[NODE_INDEX]],
                                          cycle_exit_identifier=set())  # range  far_node  sink_node 

    def _do_forward_path_exploration(self, node: py2neo.Node, cfg_pdg_path: set = set(), path_conditions: set = set(),
                                     has_source=False, threshold=None, cycle_exit_identifier: set = None, **kwargs):
        #  source 
        # forward  

        if self.sources.__len__() == 0:
            return None
        
        if cycle_exit_identifier is None:
            cycle_exit_identifier = {(-0xcaff, -0xcaff)}
        if threshold is None:
            threshold = [-0xff, 0xffff]
        threshold_bottom, threshold_upper = threshold
        #  farnode  farward exploration
        if node is None or node.labels.__str__() != ":" + LABEL_AST:
            return None
        if node[NODE_INDEX] < threshold_bottom or node[NODE_INDEX] > threshold_upper:
            return None
        #  node 
        node = self._find_outside_exit_identifier(cycle_exit_identifier, node)
        if node[NODE_LINENO] is None:
            return None

        if node[NODE_INDEX] in self.pdg_digraph.nodes.keys():   #  cfg_pdg_path 
            cfg_pdg_path.add(node[NODE_INDEX])
            if node[NODE_INDEX] in self.sources:
                has_source = True

        #   node  sink sink forward exploration 
        if node[NODE_INDEX] >= self.anchor_node_root[NODE_INDEX]:
            if self.anchor_node_root[NODE_INDEX] in cfg_pdg_path and \
                has_source:
                path_to_add = sorted(cfg_pdg_path)
                path_to_add[-1] = self.anchor_node_ast[NODE_INDEX]
                conditions_to_add = sorted(path_conditions)
                if (path_to_add, conditions_to_add) not in self.context_series:
                    self.context_series.append((path_to_add, conditions_to_add))
            return None

        parent_node = self.analyzer.ast_step.get_parent_node(node)
        if parent_node[NODE_TYPE] in {TYPE_WHILE}:  
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                # source_rels = [i for i, in self.analyzer.run(
                #     f"MATCH P = (S:AST) - [:REACHES*1..] -> (C:AST) WHERE S.id in {list(self.sources).__str__()} " + \
                #     f"AND C.id={node[NODE_INDEX]} RETURN P"
                # )]
                cypher = (
                    f"MATCH (S:AST), (C:AST {{id: {node[NODE_INDEX]}}}) "
                    f"WHERE S.id IN {list(self.sources)} "
                    f"MATCH P = shortestPath((S)-[:REACHES*1..]->(C)) "
                    f"RETURN P"
                )
                source_rels = [i for i, in self.analyzer.run(cypher)]
                if source_rels or self.analyzer.ast_step.find_sources(node) or self.analyzer.ast_step.find_custom_sources(node, self.custom_sources):
                    path_conditions.add(node[NODE_INDEX])
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[1].end_node))
                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper]) # cfg_rels[0]  true cfg_rels[0].end_node 
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                #  reaches*1..  source 
                # MATCH (S:AST {id: 273}), (C:AST {id: 297})
                # MATCH P = shortestPath((S)-[:REACHES*1..]->(C))
                # RETURN P
                # shortestPath 

                # source_rels = [i for i, in self.analyzer.run(
                #     f"MATCH P = (S:AST) - [:REACHES*1..] -> (C:AST) WHERE S.id in {list(self.sources).__str__()} " + \
                #     f"AND C.id={node[NODE_INDEX]} RETURN P"
                # )]  #  source  def  condition node  
                
                # MATCH (S:AST), (C:AST {id: 297})
                # where S.id in [128, 191, 226, 353, 164, 264, 137, 173, 209, 146, 437, 182, 217, 155, 255]
                # MATCH P = shortestPath((S)-[:REACHES*1..]->(C))
                # RETURN P
                cypher = (
                    f"MATCH (S:AST), (C:AST {{id: {node[NODE_INDEX]}}}) "
                    f"WHERE S.id IN {list(self.sources)} "
                    f"MATCH P = shortestPath((S)-[:REACHES*1..]->(C)) "
                    f"RETURN P"
                )
                source_rels = [i for i, in self.analyzer.run(cypher)]
                
                if source_rels or self.analyzer.ast_step.find_sources(node) or self.analyzer.ast_step.find_custom_sources(node, self.custom_sources):
                    path_conditions.add(node[NODE_INDEX])
                cfg_rel_true, cfg_rel_false = cfg_rels
                self._do_forward_path_exploration(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cfg_pdg_path=cfg_pdg_path, cycle_exit_identifier=cycle_exit_identifier,
                        path_conditions=path_conditions, has_source=has_source,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_true['flowLabel']},
                )
                if node[NODE_INDEX] in path_conditions:
                    path_conditions.remove(node[NODE_INDEX])
                self._do_forward_path_exploration(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cfg_pdg_path=cfg_pdg_path, cycle_exit_identifier=cycle_exit_identifier,
                        path_conditions=path_conditions, has_source=has_source,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_false['flowLabel']},
                )
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_FOR} and node[NODE_CHILDNUM] == 1:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add(
                        (self.analyzer.ast_step.get_ith_child_node(parent_node, i=2), cfg_rels[1].end_node))

                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif node[NODE_TYPE] in {TYPE_FOREACH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                if cfg_rels[0]['flowLabel'] == 'complete':
                    complete_index, next_index = 0, 1
                else:
                    complete_index, next_index = 1, 0
                cfg_rel = cfg_rels[next_index]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[complete_index].end_node))
                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_TRY}:
            pass
        elif parent_node[NODE_TYPE] in {TYPE_SWITCH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels[-1][CFG_EDGE_FLOW_LABEL] == 'default':
                cfg_rels[-1][
                    CFG_EDGE_FLOW_LABEL] = f"! ( in_array( {TMP_PARAM_FOR_SWITCH},{[i['flowLabel'] for i in cfg_rels[:-2]]}) )"
            for index in range(cfg_rels.__len__()):
                self._do_forward_path_exploration(node=cfg_rels[index].end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rels[index].start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper],
                                                  edge_property={"flowLabel": f"\'{cfg_rels[index]['flowLabel']}\'"})
        else:
            cfg_next_node = self.analyzer.cfg_step.find_successors(node)
            if cfg_next_node.__len__() == 0:
                return
            cfg_next_node = cfg_next_node[-1]
            if node[NODE_TYPE] in {TYPE_EXIT}:
                self._do_forward_path_exploration(node=cfg_next_node, cfg_pdg_path=cfg_pdg_path, 
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=None,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                self._do_forward_path_exploration(node=cfg_next_node, cfg_pdg_path=cfg_pdg_path, 
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
        if node[NODE_INDEX] in cfg_pdg_path:
            cfg_pdg_path.remove(node[NODE_INDEX])
        if node[NODE_INDEX] in path_conditions:
            path_conditions.remove(node[NODE_INDEX])

    def _find_outside_exit_identifier(self, cycle_exit_identifier, input_node):
        for _cycle_exit_identifier in cycle_exit_identifier:
            if input_node == _cycle_exit_identifier[0]:
                input_node = self._find_outside_exit_identifier(cycle_exit_identifier, _cycle_exit_identifier[1])
        return input_node
    


def save_pdg_graph(G, file_path="pdg_graph.png"):
    """
     PDG 
     taint_param
    """
    if G.number_of_nodes() == 0:
        print("⚠️ Graph is empty, nothing to draw.")
        return

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(G, seed=42)  #  shell_layout/circular_layout

    # ---  ---
    nx.draw_networkx_nodes(G, pos, node_color="#90CAF9", node_size=900, edgecolors='black')

    # ---  ---
    nx.draw_networkx_edges(G, pos, arrowstyle="->", arrowsize=15, edge_color="#555")

    # ---  ---
    node_labels = {}
    for n, attr in G.nodes(data=True):
        label = str(n)
        if 'lineno' in attr:
            label += f" (L{attr['lineno']})"
        node_labels[n] = label
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=9)

    # ---  taint_param ---
    edge_labels = {}
    for u, v, attr in G.edges(data=True):
        if 'taint_param' in attr and attr['taint_param']:
            edge_labels[(u, v)] = attr['taint_param']
        else:
            edge_labels[(u, v)] = ''
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color="red", font_size=8)

    plt.title("Program Dependence Graph (PDG)")
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(file_path, dpi=300)
    plt.close()
    print(f"✅ PDG graph saved to {file_path}")


from typing import List, Tuple

def _format_taint(taint_param) -> str:
    """ taint_param  str / list / set / None"""
    if taint_param is None:
        return "?"
    if isinstance(taint_param, str):
        # 
        return taint_param
    if isinstance(taint_param, (set, list, tuple)):
        # 
        return ",".join(sorted(str(x) for x in taint_param))
    # 
    return str(taint_param)


def extract_pdg_paths(G: nx.DiGraph, start_nodes=None, max_depth=200) -> List[List[Tuple[str, int]]]:
    """
     PDG  G  start_nodes  list of paths
     [(var, lineno), ...]
      -  var  "?"
      -  var  taint_param
     start_nodes  None G 0sources
    """
    if G.number_of_nodes() == 0:
        return []

    # 
    if start_nodes is None:
        start_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
    else:
        # 
        start_nodes = list(start_nodes)

    if not start_nodes:  #  source
        start_nodes = list(G.nodes())

    results = []

    def dfs(current, visited, path_pairs):
        """
        visited: set of visited node ids
        path_pairs: list of tuples currently [(var, lineno), ...]
        """
        if len(visited) > max_depth:
            # 
            results.append(list(path_pairs))
            return

        # 
        successors = [nbr for nbr in G.successors(current) if nbr not in visited]
        if not successors:
            # 
            results.append(list(path_pairs))
            return

        for nbr in successors:
            #  taint_param set
            edge_data = G.get_edge_data(current, nbr, default={})
            taint = edge_data.get('taint_param', None)

            taint_str = _format_taint(taint)

            nbr_lineno = G.nodes[nbr].get('lineno', '?')
            path_pairs.append((taint_str, nbr_lineno))
            visited.add(nbr)
            dfs(nbr, visited, path_pairs)
            visited.remove(nbr)
            path_pairs.pop()

    for src in start_nodes:
        #  lineno
        src_lineno = G.nodes[src].get('lineno', '?')
        #  path var  "?"
        initial_path = [("?", src_lineno)]
        visited = {src}
        dfs(src, visited, initial_path)

    fixed_results = []
    for path in results:
        if len(path) >= 2:
            second_var, _ = path[1]
            if second_var and second_var != "?":
                #  var 
                path[0] = (second_var, path[0][1])
        fixed_results.append(path)

    return fixed_results


def print_pdg_paths(G: nx.DiGraph, start_nodes=None, max_depth=200):
    """
    
    """
    paths = extract_pdg_paths(G, start_nodes=start_nodes, max_depth=max_depth)

    if not paths:
        print("⚠️ No paths extracted from PDG.")
        return

    path_str_list = []
    for idx, p in enumerate(paths, 1):
        formatted = " -> ".join(f"({var}, {lineno})" for var, lineno in p)
        print(f"[Path {idx}] {formatted}")
        path_str_list.append(f"[Path {idx}] {formatted}\n")

    return path_str_list