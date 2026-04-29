# intelligence/attack_graph/engine.py
# ──────────────────────────────────────────────────────────────────────────────
# ADVANCED ATTACK GRAPH ENGINE — Comprehensive vulnerability chaining and
# attack path analysis with MITRE ATT&CK mapping and probabilistic modeling
# ──────────────────────────────────────────────────────────────────────────────

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict, deque
import heapq
import math

logger = logging.getLogger(__name__)

# MITRE ATT&CK Technique Mapping
MITRE_TECHNIQUES = {
    "xss": "T1059.007",  # Client-Side Execution: JavaScript
    "sqli": "T1190",     # Exploit Public-Facing Application
    "lfi": "T1221",      # Template Injection
    "rce": "T1203",      # Exploitation for Client Execution
    "idor": "T1210",     # Exploitation of Remote Services
    "ssrf": "T1199",     # Trusted Relationship
    "cors": "T1134",     # Access Token Manipulation
    "redirect": "T1204", # User Execution
}

# Vulnerability chaining rules with probabilities
CHAINING_RULES = [
    # (source_type, target_type, relationship, probability, description)
    (["xss", "cross-site scripting"], ["admin", "privilege"], "session_hijack_to_admin", 0.85,
     "XSS can hijack admin sessions to gain privileged access"),
    
    (["sqli", "sql injection"], ["sensitive", "data", "credential"], "data_exfiltration", 0.90,
     "SQL injection can extract sensitive data and credentials"),
    
    (["sqli", "sql injection"], ["admin", "privilege"], "auth_bypass_to_admin", 0.75,
     "SQL injection can bypass authentication to access admin functionality"),
    
    (["ssti", "template injection"], ["rce", "command"], "potential_rce", 0.80,
     "Server-side template injection can lead to remote code execution"),
    
    (["lfi", "file inclusion"], ["credential", "config"], "credential_harvest", 0.70,
     "Local file inclusion can harvest credentials from config files"),
    
    (["redirect", "open redirect"], ["xss", "phishing"], "phishing_chain", 0.65,
     "Open redirect can facilitate phishing attacks leading to XSS"),
    
    (["cors", "misconfiguration"], ["xss", "sensitive"], "cross_origin_data_theft", 0.60,
     "CORS misconfiguration enables cross-origin data theft via XSS"),
    
    (["idor", "direct object"], ["sensitive", "data"], "unauthorized_data_access", 0.95,
     "IDOR allows unauthorized access to sensitive data objects"),
    
    (["ssrf", "server request"], ["internal", "cloud"], "internal_service_access", 0.85,
     "SSRF provides access to internal services and cloud metadata"),
    
    (["rce", "command injection"], ["lateral", "pivot"], "lateral_movement", 0.75,
     "Command injection enables lateral movement within the network"),
]

class AttackGraph:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.adjacency_list = defaultdict(list)
        self.node_map = {}  # Quick node lookup
        self.impact_scores = {}

    def add_node(self, vuln: Dict) -> Dict:
        """Add a vulnerability node with enhanced metadata"""
        node_id = len(self.nodes)
        node = {
            "id": node_id,
            "type": vuln.get("type", "").lower(),
            "subtype": vuln.get("subtype", "").lower(),
            "url": vuln.get("url", ""),
            "severity": vuln.get("severity", "Medium"),
            "confidence": vuln.get("confidence", 0.5),
            "evidence": vuln.get("evidence", "")[:200],
            "mitre_technique": self._map_mitre_technique(vuln),
            "asset_criticality": self._assess_asset_criticality(vuln),
            "exploit_complexity": self._assess_exploit_complexity(vuln),
        }
        self.nodes.append(node)
        self.node_map[node_id] = node
        return node

    def _map_mitre_technique(self, vuln: Dict) -> str:
        """Map vulnerability to MITRE ATT&CK technique"""
        vuln_type = vuln.get("type", "").lower()
        for technique, mitre_id in MITRE_TECHNIQUES.items():
            if technique in vuln_type:
                return mitre_id
        return "T1199"  # Default: Trusted Relationship

    def _assess_asset_criticality(self, vuln: Dict) -> str:
        """Assess the criticality of the affected asset"""
        url = vuln.get("url", "").lower()
        vuln_type = vuln.get("type", "").lower()
        
        if any(keyword in url for keyword in ["admin", "login", "auth", "api", "database"]):
            return "Critical"
        elif any(keyword in url for keyword in ["user", "profile", "payment", "order"]):
            return "High"
        elif any(keyword in vuln_type for keyword in ["rce", "sqli", "xss"]):
            return "High"
        else:
            return "Medium"

    def _assess_exploit_complexity(self, vuln: Dict) -> str:
        """Assess complexity of exploiting this vulnerability"""
        vuln_type = vuln.get("type", "").lower()
        confidence = vuln.get("confidence", 0.5)
        
        if confidence > 0.8:
            return "Low"
        elif any(keyword in vuln_type for keyword in ["xss", "idor", "cors"]):
            return "Low"
        elif any(keyword in vuln_type for keyword in ["sqli", "lfi", "redirect"]):
            return "Medium"
        else:
            return "High"

    def build(self, findings: List[Dict]) -> Dict:
        """Build comprehensive attack graph from findings"""
        self.nodes = []
        self.edges = []
        self.adjacency_list = defaultdict(list)
        self.node_map = {}
        
        # Add all vulnerability nodes
        for finding in findings:
            self.add_node(finding)
        
        # Build edges based on chaining rules
        for i, source_node in enumerate(self.nodes):
            for j, target_node in enumerate(self.nodes):
                if i == j:
                    continue
                
                relationship = self._can_chain(source_node, target_node)
                if relationship:
                    edge = {
                        "from": source_node["id"],
                        "to": target_node["id"],
                        "type": relationship["relationship"],
                        "probability": relationship["probability"],
                        "description": relationship["description"],
                        "weight": self._calculate_edge_weight(source_node, target_node, relationship)
                    }
                    self.edges.append(edge)
                    self.adjacency_list[source_node["id"]].append(
                        (target_node["id"], edge["weight"])
                    )
        
        # Calculate impact scores for all nodes
        self._calculate_impact_scores()
        
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "metrics": self._calculate_graph_metrics(),
            "critical_paths": self.find_critical_paths(),
            "attack_clusters": self._find_attack_clusters()
        }

    def _can_chain(self, source: Dict, target: Dict) -> Optional[Dict]:
        """Determine if two vulnerabilities can be chained with probability"""
        source_type = source["type"].lower()
        target_type = target["type"].lower()
        source_url = source["url"].lower()
        target_url = target["url"].lower()
        
        for rule in CHAINING_RULES:
            source_patterns, target_patterns, relationship, probability, description = rule
            
            # Check if source matches any pattern
            source_match = any(pattern in source_type for pattern in source_patterns)
            
            # Check if target matches any pattern
            target_match = any(pattern in target_type for pattern in target_patterns)
            
            # Additional context-based matching
            context_match = self._check_context_match(source, target, relationship)
            
            if source_match and target_match and context_match:
                # Adjust probability based on confidence and context
                adjusted_prob = probability * source["confidence"] * self._context_adjustment(source, target)
                
                return {
                    "relationship": relationship,
                    "probability": round(adjusted_prob, 2),
                    "description": description
                }
        
        return None

    def _check_context_match(self, source: Dict, target: Dict, relationship: str) -> bool:
        """Check if vulnerabilities contextually make sense to chain"""
        source_url = source["url"].lower()
        target_url = target["url"].lower()
        
        # Same domain or related context
        if source_url and target_url:
            source_domain = self._extract_domain(source_url)
            target_domain = self._extract_domain(target_url)
            
            if source_domain != target_domain:
                # Cross-domain chaining is less likely
                return relationship in ["phishing_chain", "cross_origin_data_theft"]
        
        return True

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        try:
            return urlparse(url).netloc
        except:
            return ""

    def _context_adjustment(self, source: Dict, target: Dict) -> float:
        """Adjust probability based on contextual factors"""
        adjustment = 1.0
        
        # Same domain increases probability
        if source["url"] and target["url"]:
            source_domain = self._extract_domain(source["url"])
            target_domain = self._extract_domain(target["url"])
            if source_domain == target_domain:
                adjustment *= 1.2
        
        # High confidence increases probability
        adjustment *= (0.5 + source["confidence"])
        
        # Critical assets increase probability
        if target["asset_criticality"] == "Critical":
            adjustment *= 1.3
        
        return min(adjustment, 2.0)  # Cap at 2.0

    def _calculate_edge_weight(self, source: Dict, target: Dict, relationship: Dict) -> float:
        """Calculate weight for graph traversal"""
        base_weight = 1.0 / relationship["probability"]
        
        # Adjust based on exploit complexity
        complexity_weights = {"Low": 1.0, "Medium": 1.5, "High": 2.0}
        weight = base_weight * complexity_weights.get(source["exploit_complexity"], 1.0)
        
        return round(weight, 2)

    def _calculate_impact_scores(self):
        """Calculate impact scores for all nodes using PageRank-like algorithm"""
        # Initialize scores based on severity
        initial_scores = {}
        for node in self.nodes:
            severity_weights = {"Critical": 10.0, "High": 6.0, "Medium": 3.0, "Low": 1.0}
            initial_scores[node["id"]] = severity_weights.get(node["severity"], 1.0) * node["confidence"]
        
        # Propagate scores through the graph
        scores = initial_scores.copy()
        for _ in range(10):  # 10 iterations for convergence
            new_scores = initial_scores.copy()
            for edge in self.edges:
                source_score = scores[edge["from"]]
                weight = 1.0 / edge["weight"]
                new_scores[edge["to"]] += source_score * weight * edge["probability"]
            
            # Normalize scores
            max_score = max(new_scores.values()) if new_scores else 1.0
            if max_score > 0:
                scores = {k: v / max_score * 10 for k, v in new_scores.items()}
        
        self.impact_scores = scores

    def _calculate_graph_metrics(self) -> Dict:
        """Calculate graph-level metrics"""
        if not self.nodes:
            return {}
        
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "connectivity_ratio": len(self.edges) / max(1, len(self.nodes)),
            "max_impact_score": max(self.impact_scores.values()) if self.impact_scores else 0,
            "average_impact": sum(self.impact_scores.values()) / len(self.impact_scores) if self.impact_scores else 0,
            "critical_nodes": sum(1 for score in self.impact_scores.values() if score >= 7.0),
        }

    def find_attack_paths(self, max_paths: int = 10) -> List[Dict]:
        """Find all potential attack paths with Dijkstra's algorithm"""
        paths = []
        
        # Find all entry points (nodes with no incoming edges)
        entry_points = []
        has_incoming = set()
        for edge in self.edges:
            has_incoming.add(edge["to"])
        
        for node in self.nodes:
            if node["id"] not in has_incoming:
                entry_points.append(node["id"])
        
        # Find paths from each entry point to high-impact nodes
        for start_id in entry_points:
            # Use Dijkstra to find shortest paths to high-impact nodes
            distances = {node_id: float('inf') for node_id in range(len(self.nodes))}
            distances[start_id] = 0
            predecessors = {node_id: None for node_id in range(len(self.nodes))}
            
            pq = [(0, start_id)]
            while pq:
                current_dist, current_id = heapq.heappop(pq)
                
                if current_dist > distances[current_id]:
                    continue
                
                for neighbor_id, weight in self.adjacency_list[current_id]:
                    distance = current_dist + weight
                    if distance < distances[neighbor_id]:
                        distances[neighbor_id] = distance
                        predecessors[neighbor_id] = current_id
                        heapq.heappush(pq, (distance, neighbor_id))
            
            # Find paths to high-impact nodes
            for target_id, impact_score in self.impact_scores.items():
                if impact_score >= 5.0 and distances[target_id] < float('inf'):
                    path = self._reconstruct_path(predecessors, target_id)
                    if path:
                        paths.append({
                            "path": path,
                            "total_risk": self._calculate_path_risk(path),
                            "exploit_complexity": self._calculate_path_complexity(path),
                            "impact_score": impact_score
                        })
        
        # Sort by risk and return top paths
        paths.sort(key=lambda x: x["total_risk"], reverse=True)
        return paths[:max_paths]

    def _reconstruct_path(self, predecessors: Dict[int, Optional[int]], target_id: int) -> List[Dict]:
        """Reconstruct path from predecessors dictionary"""
        path = []
        current_id = target_id
        
        while current_id is not None:
            path.insert(0, self.node_map[current_id])
            current_id = predecessors[current_id]
        
        return path if len(path) > 1 else []

    def _calculate_path_risk(self, path: List[Dict]) -> float:
        """Calculate total risk for an attack path"""
        if not path:
            return 0.0
        
        risk = 1.0
        for i in range(len(path) - 1):
            source_id = path[i]["id"]
            target_id = path[i + 1]["id"]
            
            # Find the edge between these nodes
            for edge in self.edges:
                if edge["from"] == source_id and edge["to"] == target_id:
                    risk *= edge["probability"]
                    break
        
        return round(risk * self.impact_scores[path[-1]["id"]], 2)

    def _calculate_path_complexity(self, path: List[Dict]) -> str:
        """Calculate overall complexity for an attack path"""
        complexities = [node["exploit_complexity"] for node in path]
        
        if any(c == "High" for c in complexities):
            return "High"
        elif any(c == "Medium" for c in complexities):
            return "Medium"
        else:
            return "Low"

    def find_critical_paths(self) -> List[Dict]:
        """Find the most critical attack paths"""
        return self.find_attack_paths(max_paths=5)

    def _find_attack_clusters(self) -> List[Dict]:
        """Find clusters of related attacks using connected components"""
        visited = set()
        clusters = []
        
        for node in self.nodes:
            if node["id"] not in visited:
                cluster = self._bfs_cluster(node["id"], visited)
                if cluster:
                    clusters.append({
                        "nodes": cluster,
                        "size": len(cluster),
                        "average_impact": sum(self.impact_scores[n["id"]] for n in cluster) / len(cluster),
                        "primary_types": self._get_cluster_types(cluster)
                    })
        
        return clusters

    def _bfs_cluster(self, start_id: int, visited: Set[int]) -> List[Dict]:
        """Find connected cluster using BFS"""
        cluster = []
        queue = deque([start_id])
        visited.add(start_id)
        
        while queue:
            current_id = queue.popleft()
            cluster.append(self.node_map[current_id])
            
            for neighbor_id, _ in self.adjacency_list[current_id]:
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append(neighbor_id)
        
        return cluster

    def _get_cluster_types(self, cluster: List[Dict]) -> List[str]:
        """Get primary vulnerability types in a cluster"""
        type_count = defaultdict(int)
        for node in cluster:
            type_count[node["type"]] += 1
        
        return sorted(type_count.keys(), key=lambda x: type_count[x], reverse=True)[:3]

    def to_cytoscape(self) -> List[Dict]:
        """Convert to Cytoscape.js format for visualization"""
        elements = []
        
        for node in self.nodes:
            elements.append({
                "data": {
                    "id": str(node["id"]),
                    "label": node["type"],
                    "severity": node["severity"],
                    "impact": self.impact_scores.get(node["id"], 0),
                    "type": "vulnerability"
                }
            })
        
        for edge in self.edges:
            elements.append({
                "data": {
                    "id": f"{edge['from']}-{edge['to']}",
                    "source": str(edge["from"]),
                    "target": str(edge["to"]),
                    "label": edge["type"],
                    "probability": edge["probability"],
                    "weight": edge["weight"]
                }
            })
        
        return elements
