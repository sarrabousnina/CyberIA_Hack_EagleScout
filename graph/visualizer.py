"""Interactive graph visualization using Pyvis."""

import os
from typing import Dict, Any, List
from pyvis.network import Network
import networkx as nx


class TopologyVisualizer:
    """
    Create interactive visualizations of infrastructure topology using Pyvis.

    Generates HTML files with clickable nodes showing CVEs, risk scores, and attack paths.
    """

    def __init__(
        self,
        output_dir: str = "visualizations",
        height: str = "600px",
        width: str = "100%"
    ):
        """
        Initialize topology visualizer.

        Args:
            output_dir: Directory to save HTML files
            height: Graph height
            width: Graph width
        """
        self.output_dir = output_dir
        self.height = height
        self.width = width

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

    def _get_node_color(self, node_data: Dict[str, Any]) -> str:
        """
        Determine node color based on attributes.

        Args:
            node_data: Node attributes dictionary

        Returns:
            Hex color code
        """
        # Critical assets: red
        if node_data.get('critical', False):
            return '#ff4444'

        # Exposed components: orange
        if node_data.get('exposed', False):
            return '#ff9944'

        # High risk: yellow
        risk = node_data.get('risk_score', 0)
        if risk >= 7:
            return '#ffcc00'

        # Medium risk: light blue
        if risk >= 4:
            return '#66b3ff'

        # Low risk: green
        return '#66cc66'

    def _get_node_size(self, node_data: Dict[str, Any]) -> int:
        """
        Determine node size based on importance.

        Args:
            node_data: Node attributes dictionary

        Returns:
            Node size (integer)
        """
        base_size = 30

        # Increase size for critical or exposed nodes
        if node_data.get('critical', False):
            return base_size + 20
        if node_data.get('exposed', False):
            return base_size + 10

        # Increase size based on number of CVEs
        cve_count = len(node_data.get('cves', []))
        return base_size + min(cve_count * 5, 15)

    def _format_node_title(self, node_name: str, node_data: Dict[str, Any]) -> str:
        """
        Format HTML title for node (shown on hover).

        Args:
            node_name: Node name
            node_data: Node attributes

        Returns:
            HTML string
        """
        title_parts = [
            f"<b>{node_name}</b>",
            f"Type: {node_data.get('type', 'unknown')}",
            f"Version: {node_data.get('version', 'unknown')}",
        ]

        if node_data.get('exposed', False):
            title_parts.append("<span style='color:orange'>⚠ EXPOSED TO INTERNET</span>")

        if node_data.get('critical', False):
            title_parts.append("<span style='color:red'>★ CRITICAL ASSET</span>")

        risk = node_data.get('risk_score', 0)
        title_parts.append(f"Risk Score: {risk:.1f}/10")

        cve_count = len(node_data.get('cves', []))
        if cve_count > 0:
            title_parts.append(f"CVEs: {cve_count}")

        return "<br>".join(title_parts)

    def _format_node_label(self, node_name: str, node_data: Dict[str, Any]) -> str:
        """
        Format node label (shown on graph).

        Args:
            node_name: Node name
            node_data: Node attributes

        Returns:
            Label string
        """
        # Use component type if available, otherwise name
        comp_type = node_data.get('type', 'unknown')
        return f"{node_name}\n({comp_type})"

    def create_topology_graph(
        self,
        nx_graph: nx.DiGraph,
        output_filename: str = "topology.html"
    ) -> str:
        """
        Create interactive topology visualization.

        Args:
            nx_graph: NetworkX DiGraph
            output_filename: Output HTML filename

        Returns:
            Path to generated HTML file
        """
        # Create Pyvis network
        net = Network(
            height=self.height,
            width=self.width,
            directed=True,
            bgcolor='#ffffff'
        )

        # Add nodes
        for node, data in nx_graph.nodes(data=True):
            color = self._get_node_color(data)
            size = self._get_node_size(data)
            title = self._format_node_title(node, data)
            label = self._format_node_label(node, data)

            net.add_node(
                node,
                title=title,
                label=label,
                color=color,
                size=size,
                **data
            )

        # Add edges
        for source, target, data in nx_graph.edges(data=True):
            protocol = data.get('protocol', 'UNKNOWN')
            title = f"{source} → {target}<br>Protocol: {protocol}"

            net.add_edge(
                source,
                target,
                title=title,
                label=protocol,
                color='#888888',
                arrows='to'
            )

        # Set physics options for better layout
        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -8000,
              "centralGravity": 0.3,
              "springLength": 150,
              "springConstant": 0.04
            }
          },
          "nodes": {
            "font": {
              "size": 12
            }
          },
          "edges": {
            "smooth": {
              "type": "cubicBezier",
              "forceDirection": "horizontal"
            }
          }
        }
        """)

        # Save to file
        output_path = os.path.join(self.output_dir, output_filename)
        net.save_graph(output_path)

        print(f"Topology graph saved to: {output_path}")

        return output_path

    def create_attack_path_graph(
        self,
        nx_graph: nx.DiGraph,
        attack_paths: List[Dict[str, Any]],
        output_filename: str = "attack_paths.html"
    ) -> str:
        """
        Create visualization highlighting attack paths.

        Args:
            nx_graph: NetworkX DiGraph
            attack_paths: List of attack path dictionaries
            output_filename: Output HTML filename

        Returns:
            Path to generated HTML file
        """
        # Create Pyvis network
        net = Network(
            height=self.height,
            width=self.width,
            directed=True,
            bgcolor='#ffffff'
        )

        # Track which nodes are in attack paths
        nodes_in_paths = set()
        for path in attack_paths:
            for node in path['path']:
                nodes_in_paths.add(node)

        # Add nodes
        for node, data in nx_graph.nodes(data=True):
            # Highlight nodes in attack paths
            if node in nodes_in_paths:
                color = '#ff4444'  # Red for nodes in attack paths
                size = self._get_node_size(data) + 10
            else:
                color = self._get_node_color(data)
                size = self._get_node_size(data)

            title = self._format_node_title(node, data)
            label = self._format_node_label(node, data)

            net.add_node(
                node,
                title=title,
                label=label,
                color=color,
                size=size,
                **data
            )

        # Add edges
        for source, target, data in nx_graph.edges(data=True):
            protocol = data.get('protocol', 'UNKNOWN')
            title = f"{source} → {target}<br>Protocol: {protocol}"

            # Highlight edges in attack paths
            edge_in_path = False
            for path in attack_paths:
                path_nodes = path['path']
                for i in range(len(path_nodes) - 1):
                    if path_nodes[i] == source and path_nodes[i + 1] == target:
                        edge_in_path = True
                        break

            if edge_in_path:
                color = '#ff0000'  # Red for edges in attack paths
                width = 3
            else:
                color = '#cccccc'  # Light gray for other edges
                width = 1

            net.add_edge(
                source,
                target,
                title=title,
                label=protocol,
                color=color,
                width=width,
                arrows='to'
            )

        # Set physics options
        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -8000,
              "centralGravity": 0.3,
              "springLength": 150,
              "springConstant": 0.04
            }
          }
        }
        """)

        # Save to file
        output_path = os.path.join(self.output_dir, output_filename)
        net.save_graph(output_path)

        print(f"Attack path graph saved to: {output_path}")

        return output_path


if __name__ == "__main__":
    # Test the visualizer
    import networkx as nx

    # Create test graph
    G = nx.DiGraph()
    G.add_node('nginx', type='web_server', version='1.18.0', exposed=True, critical=False, risk_score=7, cves=[{'cve_id': 'CVE-2021-1234'}])
    G.add_node('app', type='application', version='2.0', exposed=False, critical=False, risk_score=5, cves=[])
    G.add_node('db', type='database', version='12.4', exposed=False, critical=True, risk_score=3, cves=[])
    G.add_edge('nginx', 'app', protocol='HTTP')
    G.add_edge('app', 'db', protocol='TCP')

    # Create visualizations
    visualizer = TopologyVisualizer()
    visualizer.create_topology_graph(G, "test_topology.html")

    # Test with attack paths
    attack_paths = [
        {
            'path': ['nginx', 'app', 'db'],
            'total_risk': 15.0
        }
    ]
    visualizer.create_attack_path_graph(G, attack_paths, "test_attack_paths.html")
