"""Product name mapping for better CVE matching."""

# Maps component names to their actual software products
# This prevents false positives like "dotnet-api" matching "DotNetNuke"

COMPONENT_PRODUCT_MAP = {
    # Web servers
    'nginx': ['nginx'],
    'apache': ['apache http server', 'apache tomcat'],
    'iis': ['internet information services'],

    # Databases
    'postgres': ['postgresql'],
    'postgresql': ['postgresql'],
    'mysql': ['mysql'],
    'mariadb': ['mariadb'],
    'mongodb': ['mongodb'],
    'redis': ['redis'],
    'sqlite': ['sqlite'],
    'oracle': ['oracle database'],
    'sqlserver': ['microsoft sql server'],
    'mssql': ['microsoft sql server'],  # NOT mssql.js (Node.js)

    # Application servers
    'tomcat': ['apache tomcat'],
    'jboss': ['jboss'],
    'wildfly': ['wildfly'],
    'weblogic': ['weblogic'],
    'websphere': ['websphere'],

    # CI/CD
    'jenkins': ['jenkins'],
    'gitlab': ['gitlab'],
    'github': ['github enterprise'],

    # Message queues
    'kafka': ['apache kafka'],
    'rabbitmq': ['rabbitmq'],
    'activemq': ['apache activemq'],

    # Search engines
    'elasticsearch': ['elasticsearch'],
    'solr': ['apache solr'],

    # Healthcare specific - these are TOO GENERIC without vendor info
    'dcm4che': ['dcm4che'],
    'pacs': None,  # Too generic - could be any vendor (Philips, Sante, MedDream, etc.)
    'dicom': None,  # Too generic - could be any DICOM software

    # What to EXCLUDE (false positives)
    'dotnet': None,  # Too generic - could be anything .NET
    'api': None,     # Too generic
    'gateway': None, # Too generic
    'storage': None, # Too generic
    'db': None,      # Too generic
    'frontend': None,
    'backend': None,
    'server': None,
}


def extract_product_name(component_name: str, component_type: str) -> str:
    """
    Extract the actual software product from a component name.

    Args:
        component_name: e.g., "nginx-frontend", "mssql-patient-db"
        component_type: e.g., "web_server", "database"

    Returns:
        Product name for NVD search, or None if too generic
    """
    # Extract base name
    base_name = component_name.lower().split('-')[0]

    # Check if it's in the exclusion list
    if base_name in ['dotnet', 'api', 'gateway', 'storage', 'db', 'server', 'pacs', 'dicom']:
        # Try to use component_type instead
        type_products = {
            'web_server': ['nginx', 'apache http server'],
            'database': ['postgresql', 'mysql', 'mongodb', 'redis'],
            'api_gateway': ['kong', 'ambassador'],
            'message_queue': ['rabbitmq', 'apache kafka'],
            'gateway': None,  # Too generic
            'storage': None,  # Too generic
        }

        if component_type in type_products:
            product = type_products[component_type]
            if product:
                return product[0]

        # Still too generic - skip this component
        return None

    # Check explicit mapping
    if base_name in COMPONENT_PRODUCT_MAP:
        products = COMPONENT_PRODUCT_MAP[base_name]
        if products:
            return products[0]

    # Return base name as-is
    return base_name


def should_search_component(component_name: str, component_type: str) -> bool:
    """
    Determine if a component should be searched in NVD.

    Args:
        component_name: Component name
        component_type: Component type

    Returns:
        True if component should be searched, False if too generic
    """
    product = extract_product_name(component_name, component_type)
    return product is not None


if __name__ == "__main__":
    # Test the mapping
    test_components = [
        ('nginx-frontend', 'web_server'),
        ('mssql-patient-db', 'database'),
        ('dotnet-api', 'api_gateway'),
        ('pacs-gateway', 'gateway'),
        ('dicom-storage', 'storage'),
        ('postgres-db', 'database'),
    ]

    for name, type_ in test_components:
        product = extract_product_name(name, type_)
        should_search = should_search_component(name, type_)
        product_str = product if product else "SKIPPED (too generic)"
        print(f"{name:20} ({type_:15}) -> {product_str:30} | Search: {should_search}")
