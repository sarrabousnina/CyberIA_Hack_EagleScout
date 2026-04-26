"""Parse and validate user infrastructure JSON input."""

import json
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field, field_validator
from enum import Enum


class Sector(str, Enum):
    """Supported industry sectors."""
    BANKING = "banking"
    HEALTHCARE = "healthcare"
    TELECOM = "telecom"
    GENERAL = "general"


class Component(BaseModel):
    """A component in the infrastructure."""
    name: str = Field(..., description="Unique component name")
    type: str = Field(..., description="Component type (e.g., web_server, database)")
    version: str = Field(..., description="Software version")
    exposed: bool = Field(False, description="Whether exposed to internet")
    critical: bool = Field(False, description="Whether this is a critical asset")


class Connection(BaseModel):
    """A connection between components."""
    from_component: str = Field(..., alias="from", description="Source component name")
    to_component: str = Field(..., alias="to", description="Destination component name")
    protocol: str = Field(..., description="Connection protocol (e.g., HTTP, TCP)")


class InfrastructureConfig(BaseModel):
    """Complete infrastructure configuration."""
    sector: Sector = Field(Sector.GENERAL, description="Industry sector")
    components: List[Component] = Field(..., min_length=1, description="Infrastructure components")
    connections: List[Connection] = Field(default_factory=list, description="Component connections")

    @field_validator('components')
    @classmethod
    def unique_component_names(cls, v):
        """Ensure component names are unique."""
        names = [c.name for c in v]
        if len(names) != len(set(names)):
            raise ValueError("Component names must be unique")
        return v

    @field_validator('connections')
    @classmethod
    def valid_connections(cls, v, info):
        """Ensure connections reference existing components."""
        if not info.data:
            return v

        components = info.data.get('components', [])
        component_names = {c.name for c in components}
        for conn in v:
            if conn.from_component not in component_names:
                raise ValueError(f"Connection references unknown component: {conn.from_component}")
            if conn.to_component not in component_names:
                raise ValueError(f"Connection references unknown component: {conn.to_component}")
        return v


def parse_infrastructure_json(json_data: str) -> Dict[str, Any]:
    """
    Parse and validate infrastructure JSON.

    Args:
        json_data: JSON string containing infrastructure description

    Returns:
        Validated dictionary with parsed infrastructure data

    Raises:
        ValueError: If JSON is invalid or fails validation
    """
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")

    # Validate with Pydantic
    try:
        config = InfrastructureConfig(**data)
    except Exception as e:
        raise ValueError(f"Validation error: {e}")

    # Return as dict for easier downstream processing
    return {
        'sector': config.sector,
        'components': [
            {
                'name': c.name,
                'type': c.type,
                'version': c.version,
                'exposed': c.exposed,
                'critical': c.critical
            }
            for c in config.components
        ],
        'connections': [
            {
                'from': conn.from_component,
                'to': conn.to_component,
                'protocol': conn.protocol
            }
            for conn in config.connections
        ],
        'component_names': [c.name for c in config.components],
        'component_types': {c.name: c.type for c in config.components},
        'exposed_components': [c.name for c in config.components if c.exposed],
        'critical_components': [c.name for c in config.components if c.critical]
    }


def load_infrastructure_from_file(file_path: str) -> Dict[str, Any]:
    """
    Load and parse infrastructure JSON from file.

    Args:
        file_path: Path to JSON file

    Returns:
        Validated dictionary with parsed infrastructure data
    """
    with open(file_path, 'r') as f:
        return parse_infrastructure_json(f.read())


def get_tech_stack_components(infrastructure: Dict[str, Any]) -> List[str]:
    """
    Extract list of technology stack components for relevance filtering.

    Args:
        infrastructure: Parsed infrastructure dictionary

    Returns:
        List of component names and types for fuzzy matching
    """
    components = []
    for comp in infrastructure['components']:
        # Add component name, type, and name+version combinations
        components.append(comp['name'].lower())
        components.append(comp['type'].lower())
        components.append(f"{comp['name']} {comp['version']}".lower())
        components.append(f"{comp['type']} {comp['version']}".lower())

    return list(set(components))


if __name__ == "__main__":
    # Test with sample data
    sample_json = """
    {
        "sector": "banking",
        "components": [
            {
                "name": "nginx-frontend",
                "type": "web_server",
                "version": "1.18.0",
                "exposed": true,
                "critical": false
            },
            {
                "name": "postgres-db",
                "type": "database",
                "version": "12.4",
                "exposed": false,
                "critical": true
            }
        ],
        "connections": [
            {
                "from": "nginx-frontend",
                "to": "postgres-db",
                "protocol": "HTTP"
            }
        ]
    }
    """

    try:
        result = parse_infrastructure_json(sample_json)
        print("[OK] Valid infrastructure JSON")
        print(f"  Sector: {result['sector']}")
        print(f"  Components: {len(result['components'])}")
        print(f"  Connections: {len(result['connections'])}")
        print(f"  Tech stack: {get_tech_stack_components(result)}")
    except ValueError as e:
        print(f"[ERROR] {e}")
