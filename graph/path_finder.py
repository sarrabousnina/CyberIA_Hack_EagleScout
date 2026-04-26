"""Find critical attack paths in infrastructure graph."""

import networkx as nx
from typing import List, Dict, Any, Tuple
from collections import defaultdict


class AttackPathFinder:
    """
    Find critical attack paths from exposed entry points to critical assets.

    Uses graph traversal algorithms to identify high-risk paths through the infrastructure.
    """

    def __init__(self, graph: nx.DiGraph):
        """
        Initialize attack path finder.

        Args:
            graph: NetworkX DiGraph from TopologyBuilder
        """
        self.graph = graph

    def find_all_attack_paths(
        self,
        max_length: int = 5,
        max_paths: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Find all attack paths from exposed to critical nodes.

        Args:
            max_length: Maximum path length (number of hops)
            max_paths: Maximum number of paths to return

        Returns:
            List of attack path dictionaries with metadata
        """
        paths = []

        # Get entry points and targets
        exposed_nodes = [
            node for node, data in self.graph.nodes(data=True)
            if data.get('exposed', False)
        ]
        critical_nodes = [
            node for node, data in self.graph.nodes(data=True)
            if data.get('critical', False)
        ]

        print(f"Finding attack paths from {len(exposed_nodes)} exposed to {len(critical_nodes)} critical nodes...")

        # Find paths from each exposed to each critical node
        for source in exposed_nodes:
            for target in critical_nodes:
                try:
                    # Find all simple paths (no cycles)
                    for path in nx.all_simple_paths(self.graph, source, target, cutoff=max_length):
                        if len(paths) >= max_paths:
                            break

                        path_data = self._analyze_path(path)
                        paths.append(path_data)

                except nx.NetworkXNoPath:
                    continue

                if len(paths) >= max_paths:
                    break

            if len(paths) >= max_paths:
                break

        # Sort by path risk (descending)
        paths.sort(key=lambda p: p['total_risk'], reverse=True)

        print(f"Found {len(paths)} attack paths")

        return paths

    def _analyze_path(self, path: List[str]) -> Dict[str, Any]:
        """
        Analyze an attack path and compute risk metrics.

        Args:
            path: List of node names in the path

        Returns:
            Dictionary with path analysis
        """
        # Get node risks
        node_risks = []
        node_data = []

        for node in path:
            data = self.graph.nodes[node]
            risk = data.get('risk_score', 0)
            node_risks.append(risk)
            node_data.append({
                'name': node,
                'type': data.get('type', 'unknown'),
                'risk': risk,
                'cve_count': len(data.get('cves', []))
            })

        # Get edge protocols
        edge_protocols = []
        for i in range(len(path) - 1):
            from_node = path[i]
            to_node = path[i + 1]
            if self.graph.has_edge(from_node, to_node):
                protocol = self.graph.edges[from_node, to_node].get('protocol', 'UNKNOWN')
                edge_protocols.append(protocol)

        # Calculate path risk
        total_risk = sum(node_risks) if node_risks else 0
        avg_risk = total_risk / len(node_risks) if node_risks else 0
        max_risk = max(node_risks) if node_risks else 0

        return {
            'path': path,
            'length': len(path),
            'total_risk': total_risk,
            'avg_risk': avg_risk,
            'max_risk': max_risk,
            'node_details': node_data,
            'protocols': edge_protocols,
            'entry_point': path[0] if path else None,
            'target': path[-1] if path else None
        }

    def find_top_n_paths(self, n: int = 10, max_length: int = 5) -> List[Dict[str, Any]]:
        """
        Find top N highest-risk attack paths.

        Args:
            n: Number of top paths to return
            max_length: Maximum path length

        Returns:
            List of top N attack paths
        """
        all_paths = self.find_all_attack_paths(max_length=max_length)
        return all_paths[:n]

    def find_paths_to_component(self, component_name: str, max_length: int = 5) -> List[Dict[str, Any]]:
        """
        Find all attack paths to a specific component.

        Args:
            component_name: Target component name
            max_length: Maximum path length

        Returns:
            List of attack paths to the component
        """
        if component_name not in self.graph.nodes:
            return []

        paths = []

        # Get exposed entry points
        exposed_nodes = [
            node for node, data in self.graph.nodes(data=True)
            if data.get('exposed', False)
        ]

        # Find paths from exposed to target
        for source in exposed_nodes:
            try:
                for path in nx.all_simple_paths(self.graph, source, component_name, cutoff=max_length):
                    path_data = self._analyze_path(path)
                    paths.append(path_data)
            except nx.NetworkXNoPath:
                continue

        # Sort by risk
        paths.sort(key=lambda p: p['total_risk'], reverse=True)

        return paths

    def get_component_chain_to_critical(self, component_name: str) -> List[str]:
        """
        Get shortest path from component to any critical asset.

        Args:
            component_name: Starting component name

        Returns:
            List of node names in path, or empty list if no path
        """
        if component_name not in self.graph.nodes:
            return []

        # Get critical nodes
        critical_nodes = [
            node for node, data in self.graph.nodes(data=True)
            if data.get('critical', False)
        ]

        # Find shortest path to any critical node
        shortest_path = []
        for target in critical_nodes:
            try:
                path = nx.shortest_path(self.graph, component_name, target)
                if not shortest_path or len(path) < len(shortest_path):
                    shortest_path = path
            except nx.NetworkXNoPath:
                continue

        return shortest_path

    def calculate_attack_surface_metrics(self) -> Dict[str, Any]:
        """
        Calculate overall attack surface metrics.

        Returns:
            Dictionary with attack surface metrics
        """
        # Count exposed and critical nodes
        exposed_count = sum(
            1 for _, data in self.graph.nodes(data=True)
            if data.get('exposed', False)
        )
        critical_count = sum(
            1 for _, data in self.graph.nodes(data=True)
            if data.get('critical', False)
        )

        # Get all attack paths
        all_paths = self.find_all_attack_paths()

        if not all_paths:
            return {
                'exposed_entry_points': exposed_count,
                'critical_assets': critical_count,
                'total_attack_paths': 0,
                'avg_path_length': 0,
                'max_path_risk': 0,
                'high_risk_paths': 0
            }

        # Calculate metrics
        path_lengths = [p['length'] for p in all_paths]
        path_risks = [p['total_risk'] for p in all_paths]
        high_risk_threshold = 7.0
        high_risk_count = sum(1 for r in path_risks if r >= high_risk_threshold)

        return {
            'exposed_entry_points': exposed_count,
            'critical_assets': critical_count,
            'total_attack_paths': len(all_paths),
            'avg_path_length': sum(path_lengths) / len(path_lengths),
            'max_path_risk': max(path_risks),
            'avg_path_risk': sum(path_risks) / len(path_risks),
            'high_risk_paths': high_risk_count,
            'high_risk_threshold': high_risk_threshold
        }


if __name__ == "__main__":
    # Test with a sample graph
    import networkx as nx

    # Create test graph
    G = nx.DiGraph()
    G.add_node('nginx', type='web_server', exposed=True, critical=False, risk_score=7)
    G.add_node('app', type='application', exposed=False, critical=False, risk_score=5)
    G.add_node('db', type='database', exposed=False, critical=True, risk_score=3)
    G.add_edge('nginx', 'app', protocol='HTTP')
    G.add_edge('app', 'db', protocol='TCP')

    # Find paths
    finder = AttackPathFinder(G)
    paths = finder.find_all_attack_paths()

    print(f"\nFound {len(paths)} attack paths:")
    for i, path in enumerate(paths, 1):
        print(f"\nPath {i}:")
        print(f"  Route: {' -> '.join(path['path'])}")
        print(f"  Total Risk: {path['total_risk']:.1f}")
        print(f"  Max Risk: {path['max_risk']:.1f}")

    # Metrics
    metrics = finder.calculate_attack_surface_metrics()
    print(f"\nAttack Surface Metrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")
