"""Groq ReAct conversational agent for EagleScout."""

import os
import json
from typing import List, Dict, Any
from groq import Groq
from dotenv import load_dotenv

load_dotenv()


class ReActAgent:
    """
    ReAct (Reasoning + Acting) agent for conversational AI.

    Tools available:
    - search_cves: Search filtered CVEs by keywords
    - explain_cve: Get detailed reasoning for a specific CVE
    - show_attack_path: Display attack paths for a component
    - list_components: List all components in the infrastructure
    - get_summary: Get overall analysis summary
    """

    def __init__(self, cves: List[Dict[str, Any]], paths: List[Dict[str, Any]], infrastructure: Dict[str, Any]):
        """
        Initialize ReAct agent.

        Args:
            cves: List of analyzed CVEs
            paths: List of attack paths
            infrastructure: Infrastructure dictionary
        """
        self.cves = cves
        self.paths = paths
        self.infrastructure = infrastructure

        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            raise ValueError("GROQ_API_KEY not found in environment variables")

        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"

        # Define tools
        self.tools = {
            'search_cves': self._search_cves,
            'explain_cve': self._explain_cve,
            'show_attack_path': self._show_attack_path,
            'list_components': self._list_components,
            'get_summary': self._get_summary
        }

    def _search_cves(self, query: str) -> str:
        """
        Search CVEs by keywords.

        Args:
            query: Search query (component name, severity, MITRE tag, etc.)

        Returns:
            Search results as formatted string
        """
        query_lower = query.lower()
        results = []

        for cve in self.cves:
            # Search in multiple fields
            cve_id = cve.get('cve_id', '').lower()
            component = cve.get('affected_component', '').lower()
            description = cve.get('description', '').lower()
            mitre_tags = ' '.join(cve.get('mitre_tags', [])).lower()
            reasoning = cve.get('reasoning', {})
            risk_score = reasoning.get('risk_score', 0)

            # Check if query matches
            if (query_lower in cve_id or
                query_lower in component or
                query_lower in description or
                query_lower in mitre_tags or
                query_lower in ['high', 'medium', 'low'] and
                ((query_lower == 'high' and risk_score >= 7) or
                 (query_lower == 'medium' and 4 <= risk_score < 7) or
                 (query_lower == 'low' and risk_score < 4))):

                results.append(f"• {cve['cve_id']} | {cve.get('affected_component')} | "
                             f"Risk: {risk_score}/10 | {description[:60]}...")

        if not results:
            return f"No CVEs found matching '{query}'"

        return f"Found {len(results)} CVE(s):\n" + "\n".join(results[:10])

    def _explain_cve(self, cve_id: str) -> str:
        """
        Get detailed explanation for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)

        Returns:
            Detailed explanation
        """
        # Find CVE
        cve = None
        for c in self.cves:
            if c.get('cve_id', '').lower() == cve_id.lower():
                cve = c
                break

        if not cve:
            return f"CVE {cve_id} not found in analysis"

        reasoning = cve.get('reasoning', {})
        compliance = cve.get('compliance', {})
        mitre_tags = cve.get('mitre_tags', [])

        explanation = f"""
📋 CVE: {cve.get('cve_id')}
🎯 Affected Component: {cve.get('affected_component')}
⚠️ Risk Score: {reasoning.get('risk_score', 0)}/10
📊 Base Severity: {reasoning.get('base_severity', 0)}/10
🔄 Context Multiplier: {reasoning.get('context_multiplier', 1.0)}x

📝 Description:
{cve.get('description', 'N/A')}

🧠 Reasoning:
{reasoning.get('reasoning_trace', 'N/A')}

📊 Confidence: {reasoning.get('confidence', 0)}/5
✅ Recommended Action: {reasoning.get('recommended_action', 'N/A')}

🎯 MITRE ATT&CK: {', '.join(mitre_tags) if mitre_tags else 'N/A'}
📋 Compliance: {compliance.get('violation_risk', 'unknown')} risk
📚 Frameworks: {', '.join(compliance.get('applicable_frameworks', []))}

🔍 OTX Threat Intelligence:
   - Pulse Count: {cve.get('otx_pulse_count', 0)}
   - Active Exploitation: {'Yes' if cve.get('otx_active_exploitation') else 'No'}
"""
        return explanation.strip()

    def _show_attack_path(self, component: str) -> str:
        """
        Show attack paths for a component.

        Args:
            component: Component name

        Returns:
            Attack paths as formatted string
        """
        component_lower = component.lower()
        relevant_paths = []

        for path in self.paths:
            if component_lower in [node.lower() for node in path['path']]:
                route = " → ".join(path['path'])
                relevant_paths.append(f"Path: {route}\nTotal Risk: {path['total_risk']:.1f}/10")

        if not relevant_paths:
            return f"No attack paths found involving '{component}'"

        return f"Found {len(relevant_paths)} attack path(s):\n\n" + "\n\n".join(relevant_paths)

    def _list_components(self) -> str:
        """
        List all components in the infrastructure.

        Returns:
            Components list as formatted string
        """
        components = self.infrastructure.get('components', [])

        if not components:
            return "No components found"

        result = "Infrastructure Components:\n\n"
        for comp in components:
            flags = []
            if comp.get('exposed'):
                flags.append("🌐 EXPOSED")
            if comp.get('critical'):
                flags.append("⭐ CRITICAL")

            flags_str = " | ".join(flags) if flags else "Standard"
            result += f"• {comp['name']} ({comp['type']} v{comp.get('version', 'unknown')}) [{flags_str}]\n"

        return result.strip()

    def _get_summary(self) -> str:
        """
        Get overall analysis summary.

        Returns:
            Summary statistics
        """
        total_cves = len(self.cves)
        total_paths = len(self.paths)

        # Calculate stats
        high_risk = sum(1 for cve in self.cves if cve.get('reasoning', {}).get('risk_score', 0) >= 7)
        medium_risk = sum(1 for cve in self.cves if 4 <= cve.get('reasoning', {}).get('risk_score', 0) < 7)
        low_risk = total_cves - high_risk - medium_risk

        avg_risk = sum(cve.get('reasoning', {}).get('risk_score', 0) for cve in self.cves) / total_cves if total_cves > 0 else 0

        # Find most vulnerable component
        component_risks = {}
        for cve in self.cves:
            comp = cve.get('affected_component', 'Unknown')
            risk = cve.get('reasoning', {}).get('risk_score', 0)
            if comp not in component_risks:
                component_risks[comp] = []
            component_risks[comp].append(risk)

        most_vulnerable = max(component_risks.items(),
                            key=lambda x: sum(x[1]) / len(x[1])) if component_risks else ('N/A', 0)

        summary = f"""
📊 Analysis Summary
{'=' * 40}

Total CVEs Found: {total_cves}
Total Attack Paths: {total_paths}
Average Risk Score: {avg_risk:.1f}/10

Risk Distribution:
  🔴 High Risk (7-10): {high_risk}
  🟡 Medium Risk (4-6): {medium_risk}
  🟢 Low Risk (1-3): {low_risk}

Most Vulnerable Component: {most_vulnerable[0]} (avg risk: {sum(most_vulnerable[1])/len(most_vulnerable[1]):.1f})

Sector: {self.infrastructure.get('sector', 'unknown')}
Components: {len(self.infrastructure.get('components', []))}
"""
        return summary.strip()

    def chat(self, user_message: str) -> str:
        """
        Process user message through ReAct loop.

        Args:
            user_message: User's message

        Returns:
            Agent response
        """
        # Build system prompt
        system_prompt = """You are EagleScout, a cybersecurity assistant specializing in vulnerability intelligence and attack path analysis.

You have access to these tools:
- search_cves(query): Search CVEs by keywords (component name, severity, MITRE tag, etc.)
- explain_cve(cve_id): Get detailed explanation for a specific CVE
- show_attack_path(component): Show attack paths for a component
- list_components: List all components in the infrastructure
- get_summary: Get overall analysis summary

When the user asks a question:
1. Think about which tool(s) you need to use
2. Call the tool(s) by writing "Tool: tool_name" followed by "Input: input_value" on separate lines
3. Observe the tool output
4. Formulate a helpful response based on the tool output

If no tool is needed (general questions), answer directly from your knowledge.

IMPORTANT:
- Be concise and helpful
- Focus on actionable insights
- Highlight high-risk items
- Explain the "why" behind vulnerabilities
- If you need to use a tool, use the exact format:
  Tool: tool_name
  Input: input_value
"""

        # Build conversation history with tool results
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]

        # First call: let LLM decide which tool to use
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.3,
            max_tokens=500
        )

        agent_response = response.choices[0].message.content

        # Check if agent wants to use a tool
        tool_use = self._parse_tool_use(agent_response)

        if tool_use:
            tool_name = tool_use['tool']
            tool_input = tool_use['input']

            # Execute tool
            if tool_name in self.tools:
                tool_output = self.tools[tool_name](tool_input)

                # Feed tool output back to LLM
                messages.append({"role": "assistant", "content": agent_response})
                messages.append({"role": "user", "content": f"Tool output:\n{tool_output}\n\nPlease provide a helpful response based on this."})

                # Get final response
                final_response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.5,
                    max_tokens=800
                )

                return final_response.choices[0].message.content
            else:
                return f"Error: Unknown tool '{tool_name}'"
        else:
            # No tool needed, return direct response
            return agent_response

    def _parse_tool_use(self, response: str) -> Dict[str, str]:
        """
        Parse tool use from agent response.

        Args:
            response: Agent response text

        Returns:
            Dictionary with 'tool' and 'input' keys, or None if no tool use
        """
        lines = response.strip().split('\n')

        tool_name = None
        tool_input = None

        for i, line in enumerate(lines):
            if line.strip().startswith('Tool:') or line.strip().startswith('tool:'):
                tool_name = line.split(':', 1)[1].strip()
            elif (line.strip().startswith('Input:') or line.strip().startswith('input:')) and tool_name:
                # Get input (might span multiple lines)
                input_lines = [line.split(':', 1)[1].strip()]
                for j in range(i + 1, len(lines)):
                    if not lines[j].strip() or lines[j].strip().startswith('-'):
                        break
                    input_lines.append(lines[j].strip())

                tool_input = ' '.join(input_lines)
                break

        if tool_name and tool_input:
            return {'tool': tool_name, 'input': tool_input}

        return None


if __name__ == "__main__":
    # Test the agent
    sample_cves = [
        {
            'cve_id': 'CVE-2024-1234',
            'affected_component': 'nginx',
            'description': 'Nginx RCE vulnerability',
            'reasoning': {'risk_score': 9, 'base_severity': 8, 'context_multiplier': 1.5, 'reasoning_trace': 'High risk due to exposure', 'confidence': 5, 'recommended_action': 'Patch immediately'},
            'mitre_tags': ['TA0001/T1190'],
            'compliance': {'violation_risk': 'high', 'applicable_frameworks': ['PCI-DSS']},
            'otx_pulse_count': 15,
            'otx_active_exploitation': True
        }
    ]

    sample_paths = [
        {'path': ['internet', 'nginx', 'postgres'], 'total_risk': 8.5}
    ]

    sample_infrastructure = {
        'sector': 'banking',
        'components': [
            {'name': 'nginx', 'type': 'web_server', 'version': '1.18', 'exposed': True, 'critical': False},
            {'name': 'postgres', 'type': 'database', 'version': '12.4', 'exposed': False, 'critical': True}
        ]
    }

    agent = ReActAgent(sample_cves, sample_paths, sample_infrastructure)

    # Test queries
    queries = [
        "What's the summary?",
        "Tell me about CVE-2024-1234",
        "Show attack paths for nginx",
        "Search for high risk CVEs"
    ]

    for query in queries:
        print(f"\nUser: {query}")
        print(f"Agent: {agent.chat(query)}")
        print("-" * 80)
