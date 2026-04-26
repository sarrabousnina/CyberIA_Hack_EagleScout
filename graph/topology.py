"""Build infrastructure topology graph using NetworkX."""

import networkx as nx
from typing import Dict, List, Any


class TopologyBuilder:
    """
    Build NetworkX directed graph from infrastructure configuration.

    Nodes: components with attributes (type, version, exposed, critical, CVEs, risk scores)
    Edges: connections with protocols
    """

    def __init__(self):
        """Initialize topology builder."""
        self.graph = nx.DiGraph()

    def build_graph(self, infrastructure: Dict[str, Any]) -> nx.DiGraph:
        """
        Build directed graph from infrastructure configuration.

        Args:
            infrastructure: Parsed infrastructure dictionary

        Returns:
            NetworkX DiGraph with topology
        """
        # Create graph
        self.graph = nx.DiGraph()

        # Add nodes (components)
        for component in infrastructure.get('components', []):
            self._add_component_node(component)

        # Add edges (connections)
        for connection in infrastructure.get('connections', []):
            self._add_connection_edge(connection)

        print(f"Built topology graph: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")

        return self.graph

    def _add_component_node(self, component: Dict[str, Any]):
        """
        Add a component as a node in the graph.

        Args:
            component: Component dictionary
        """
        name = component['name']

        # Node attributes
        attributes = {
            'type': component.get('type', 'unknown'),
            'version': component.get('version', 'unknown'),
            'exposed': component.get('exposed', False),
            'critical': component.get('critical', False),
            'cves': [],  # Will be populated later
            'risk_score': 0.0,  # Will be populated later
            'base_severity': 0,
            'context_multiplier': 1.0,
            'mitre_tags': [],
            'compliance_tags': []
        }

        self.graph.add_node(name, **attributes)

    def _add_connection_edge(self, connection: Dict[str, Any]):
        """
        Add a connection as an edge in the graph.

        Args:
            connection: Connection dictionary
        """
        from_node = connection.get('from')
        to_node = connection.get('to')
        protocol = connection.get('protocol', 'UNKNOWN')

        if from_node and to_node:
            # Edge attributes
            attributes = {
                'protocol': protocol,
                'bidirectional': False
            }

            self.graph.add_edge(from_node, to_node, **attributes)

    def attach_cve_to_component(self, component_name: str, cve_data: Dict[str, Any]):
        """
        Attach CVE data to a component node.

        Args:
            component_name: Name of component
            cve_data: CVE dictionary with reasoning results
        """
        if component_name in self.graph.nodes:
            # Get existing CVEs
            existing_cves = self.graph.nodes[component_name].get('cves', [])

            # Add new CVE
            existing_cves.append(cve_data)

            # Update node attributes
            self.graph.nodes[component_name]['cves'] = existing_cves

            # Update risk score to max of all CVEs
            risk_scores = [
                cve.get('reasoning', {}).get('risk_score', 0)
                for cve in existing_cves
            ]
            if risk_scores:
                self.graph.nodes[component_name]['risk_score'] = max(risk_scores)

    def get_exposed_nodes(self) -> List[str]:
        """
        Get list of exposed nodes (entry points).

        Returns:
            List of node names
        """
        return [
            node for node, data in self.graph.nodes(data=True)
            if data.get('exposed', False)
        ]

    def get_critical_nodes(self) -> List[str]:
        """
        Get list of critical nodes (high-value assets).

        Returns:
            List of node names
        """
        return [
            node for node, data in self.graph.nodes(data=True)
            if data.get('critical', False)
        ]

    def get_component_type(self, component_name: str) -> str:
        """
        Get component type.

        Args:
            component_name: Name of component

        Returns:
            Component type
        """
        if component_name in self.graph.nodes:
            return self.graph.nodes[component_name].get('type', 'unknown')
        return 'unknown'

    def get_node_attributes(self, node_name: str) -> Dict[str, Any]:
        """
        Get all attributes for a node.

        Args:
            node_name: Name of node

        Returns:
            Dictionary of node attributes
        """
        if node_name in self.graph.nodes:
            return dict(self.graph.nodes[node_name])
        return {}

    def update_node_attribute(self, node_name: str, key: str, value: Any):
        """
        Update a single attribute on a node.

        Args:
            node_name: Name of node
            key: Attribute key
            value: Attribute value
        """
        if node_name in self.graph.nodes:
            self.graph.nodes[node_name][key] = value

    def get_graph(self) -> nx.DiGraph:
        """
        Get the NetworkX graph.

        Returns:
            NetworkX DiGraph
        """
        return self.graph

    def print_summary(self):
        """Print summary of the topology graph."""
        print("\n=== Topology Summary ===")
        print(f"Total components: {self.graph.number_of_nodes()}")
        print(f"Total connections: {self.graph.number_of_edges()}")

        exposed = self.get_exposed_nodes()
        critical = self.get_critical_nodes()

        print(f"Exposed components: {len(exposed)}")
        for node in exposed:
            node_type = self.get_component_type(node)
            print(f"  - {node} ({node_type})")

        print(f"Critical components: {len(critical)}")
        for node in critical:
            node_type = self.get_component_type(node)
            print(f"  - {node} ({node_type})")


if __name__ == "__main__":
    # Test the topology builder
    sample_infrastructure = {
        'components': [
            {'name': 'nginx-frontend', 'type': 'web_server', 'version': '1.18.0', 'exposed': True, 'critical': False},
            {'name': 'postgres-db', 'type': 'database', 'version': '12.4', 'exposed': False, 'critical': True},
            {'name': 'redis-cache', 'type': 'cache', 'version': '6.0', 'exposed': False, 'critical': False}
        ],
        'connections': [
            {'from': 'nginx-frontend', 'to': 'postgres-db', 'protocol': 'HTTP'},
            {'from': 'nginx-frontend', 'to': 'redis-cache', 'protocol': 'TCP'}
        ]
    }

    builder = TopologyBuilder()
    graph = builder.build_graph(sample_infrastructure)
    builder.print_summary()

    # Test attaching CVE
    sample_cve = {
        'cve_id': 'CVE-2021-23017',
        'reasoning': {'risk_score': 8}
    }
    builder.attach_cve_to_component('nginx-frontend', sample_cve)

    print("\nAfter attaching CVE:")
    print(f"nginx-frontend risk score: {graph.nodes['nginx-frontend']['risk_score']}")
