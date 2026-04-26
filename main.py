"""Enhanced dashboard with BM25, Groq reasoning, and interactive graph."""

import streamlit as st
import pandas as pd
import json
from datetime import datetime, timedelta
import streamlit.components.v1 as components
import os
import plotly.graph_objects as go

st.set_page_config(page_title="EagleScout", layout="wide", page_icon="🦅")

st.title("🦅 EagleScout")
st.markdown("")

# Initialize session state
if 'results_ready' not in st.session_state:
    st.session_state.results_ready = False
if 'topology_graph_path' not in st.session_state:
    st.session_state.topology_graph_path = None
if 'attack_path_graph_path' not in st.session_state:
    st.session_state.attack_path_graph_path = None

# File upload
uploaded_file = st.file_uploader("Upload infrastructure JSON", type=['json'])

if uploaded_file:
    try:
        # Parse infrastructure
        from ingestion import parse_infrastructure_json
        infrastructure = parse_infrastructure_json(uploaded_file.read().decode('utf-8'))

        st.success(f"✅ **{infrastructure['sector'].value.capitalize()}** infrastructure loaded")
        st.caption(f"{len(infrastructure['components'])} components • {len(infrastructure['connections'])} connections")

        # Analysis button
        if st.button("🔍 Analyze Vulnerabilities", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()

            try:
                # Step 1: Fetch CVEs
                status_text.text("Fetching CVEs from NVD...")
                progress_bar.progress(25)

                try:
                    from cve import NVDClient
                    nvd_client = NVDClient()

                    # Use keyword-based search (more accurate, no 90-day limit)
                    cves = nvd_client.fetch_cves_for_tech_stack(
                        tech_components=infrastructure['components'],
                        max_results_per_tech=50  # Reduced for speed
                    )
                except Exception as e:
                    st.error(f"❌ Error fetching CVEs from NVD: {e}")
                    st.info("🔧 This might be a temporary NVD API issue. Please try again in a few minutes.")
                    st.stop()

                if not cves:
                    st.warning("⚠️ No CVEs returned from NVD API")
                    st.info("The NVD database might be temporarily unavailable or rate limited.")
                    st.info("Please try again in a few minutes or check: https://nvd.nist.gov/")
                    st.stop()

                st.info(f"✅ Fetched {len(cves)} CVEs from NVD database")
                progress_bar.progress(50)

                # Step 2: BM25 + Semantic Relevance Filtering
                status_text.text("Filtering CVEs using BM25 + Semantic similarity...")

                from filter import HybridRelevanceFilter
                relevance_filter = HybridRelevanceFilter(
                    sparse_weight=0.8,  # Even more weight on exact keyword matching
                    dense_weight=0.2,   # Minimal weight on semantic similarity
                    relevance_threshold=0.6  # Very high threshold - only exact matches
                )

                # Build tech stack
                tech_stack = []
                for comp in infrastructure['components']:
                    tech_stack.append(f"{comp['name']} {comp.get('version', '')}")
                    tech_stack.append(comp['type'])
                    tech_stack.append(f"{comp['type']} {comp.get('version', '')}")

                # Fit filter
                relevance_filter.fit(tech_stack)

                # Filter CVEs
                relevant_cves, relevance_scores = relevance_filter.filter_cves(cves)

                # CRITICAL: Exact product matching with blacklists - STRICT MODE
                strictly_relevant = []

                # Blacklist of wrong products
                apache_blacklist = [
                    'apache hadoop', 'hadoop', 'hdfs', 'yarn', 'mapreduce',
                    'apache karaf', 'karaf', 'decanter',
                    'apache cassandra', 'cassandra', 'cassandra web',
                    'apache spark', 'spark',
                    'apache kafka', 'kafka',
                    'apache zookeeper', 'zookeeper',
                    'apache activemq', 'activemq',
                    'apache lucene', 'lucene',
                    'apache solr', 'solr',
                    'apache maven', 'maven',
                    'apache ant', 'ant',
                    'muntashirakon', 'appmanager',
                    'liuyu', 'liuyueyi',
                    'swoole', 'swoole-src', 'thirdparty'
                ]

                mysql_blacklist = [
                    'php', 'wordpress', 'drupal', 'joomla', 'magento',
                    'laravel', 'symfony', 'codeigniter',
                    'hustof'
                ]

                general_blacklist = [
                    'app', 'appmanager', 'application', 'framework', 'library',
                    'thirdparty', 'third-party', 'module', 'plugin', 'extension'
                ]

                for cve in relevant_cves:
                    desc = cve.get('description', '')
                    desc_lower = desc.lower()
                    affected_products = cve.get('affected_products', [])
                    cve_id = cve.get('cve_id', 'UNKNOWN')

                    relevant = False
                    matched_component = None
                    match_reason = None
                    filtered_reason = None

                    # Skip unsupported/ancient CVEs
                    if 'unsupported' in desc_lower or 'assigned' in desc_lower:
                        filtered_reason = "UNSUPPORTED CVE"
                        continue

                    cve_id_year = cve_id.split('-')[1] if len(cve_id.split('-')) > 1 else '0000'
                    if cve_id_year < '2020':
                        filtered_reason = f"Too old ({cve_id_year})"
                        continue

                    # Check against blacklists
                    for blacklist_word in apache_blacklist + mysql_blacklist + general_blacklist:
                        if blacklist_word in desc_lower:
                            filtered_reason = f"Contains '{blacklist_word}'"
                            break

                    if filtered_reason:
                        continue

                    # MUST have explicit product match
                    for comp in infrastructure['components']:
                        comp_name = comp['name'].lower()
                        base_name = comp_name.split('-')[0]

                        # EXACT product names only
                        exact_products = {
                            'apache': ['apache http server', 'apache tomcat', 'apache web server'],
                            'nginx': ['nginx'],
                            'postgres': ['postgresql', 'postgres'],
                            'mysql': ['mysql'],
                            'redis': ['redis'],
                            'jenkins': ['jenkins'],
                            'vault': ['vault', 'hashicorp vault'],
                            'tomcat': ['apache tomcat', 'tomcat']
                        }

                        products = exact_products.get(base_name, [])

                        # MUST find product in description or affected_products
                        found = False
                        for exact_product in products:
                            if exact_product in desc_lower:
                                found = True
                                match_reason = f"Found '{exact_product}' in description"
                                break

                        if not found and affected_products:
                            for product in affected_products:
                                product_lower = product.lower()
                                for exact_product in products:
                                    if product_lower.startswith(exact_product + ' ') or product_lower == exact_product:
                                        found = True
                                        match_reason = f"Match in affected_products: {product}"
                                        break
                                if found:
                                    break

                        if found:
                            relevant = True
                            matched_component = comp['name']
                            break

                    if relevant and matched_component:
                        cve['affected_component'] = matched_component
                        strictly_relevant.append(cve)

                st.info(f"🔍 BM25 filter: {len(relevant_cves)} / {len(cves)} CVEs")
                st.info(f"✅ Strict filter: {len(strictly_relevant)} / {len(relevant_cves)} CVEs actually match")

                # Show sample filtered CVEs for transparency
                if len(relevant_cves) > 0 and len(strictly_relevant) < len(relevant_cves):
                    with st.expander("🔍 Sample CVEs that were filtered (first 10)"):
                        shown = 0
                        for cve in relevant_cves[:20]:
                            if cve not in strictly_relevant:
                                desc = cve.get('description', '')[:80]
                                st.write(f"• **{cve.get('cve_id')}**: {desc}...")
                                shown += 1
                                if shown >= 10:
                                    break

                relevant_cves = strictly_relevant

                # If no matches, show clear message and stop
                if not relevant_cves:
                    st.warning("No relevant CVEs found for your infrastructure components.")
                    st.info("This is actually good news - none of the recent CVEs match your tech stack!")
                    st.info("💡 Tip: Try infrastructure with common software like Apache, nginx, MySQL, Jenkins, or PostgreSQL")
                    progress_bar.progress(100)
                    status_text.empty()
                    st.stop()

                progress_bar.progress(65)

                # CVEs are already matched in the strict filter above, skip rematching
                # Just verify we have matches
                relevant_cves = [cve for cve in relevant_cves if cve.get('affected_component')]

                progress_bar.progress(75)

                # Step 3: Groq Security Reasoning
                status_text.text("Performing security reasoning with Groq AI...")

                from reasoning import GroqSecurityReasoner
                reasoner = GroqSecurityReasoner()

                # Prepare infrastructure for reasoning
                infrastructure_copy = infrastructure.copy()
                infrastructure_copy['exposed_components'] = [
                    c['name'] for c in infrastructure['components'] if c.get('exposed')
                ]
                infrastructure_copy['critical_components'] = [
                    c['name'] for c in infrastructure['components'] if c.get('critical')
                ]

                # Batch reason (limit to 10 CVEs for speed)
                cves_to_reason = relevant_cves[:10]
                reasoning_results = reasoner.batch_reason(cves_to_reason, infrastructure_copy)

                # Attach reasoning to CVEs
                for cve in relevant_cves:
                    cve_id = cve.get('cve_id')
                    if cve_id in reasoning_results:
                        cve['reasoning'] = reasoning_results[cve_id]
                    else:
                        # Fallback reasoning
                        cvss_score = cve.get('cvss_v3_score', 5.0)
                        if cvss_score is None:
                            cvss_score = 5.0

                        is_exposed = any(
                            c['name'] == cve.get('affected_component') and c.get('exposed')
                            for c in infrastructure['components']
                        )

                        risk_score = min(10, int(cvss_score * (1.5 if is_exposed else 1.0)))

                        cve['reasoning'] = {
                            'risk_score': risk_score,
                            'base_severity': int(cvss_score),
                            'context_multiplier': 1.5 if is_exposed else 1.0,
                            'reasoning_trace': f"CVSS {cvss_score} adjusted based on exposure.",
                            'confidence': 3,
                            'recommended_action': 'Patch immediately' if risk_score >= 7 else 'Monitor and patch'
                        }

                    # MITRE tags
                    vuln_type = cve.get('description', '').lower()
                    mitre_tags = ['TA0001/T1190']  # Default
                    if 'sql injection' in vuln_type:
                        mitre_tags = ['TA0001/T1190']
                    elif 'remote code' in vuln_type or 'rce' in vuln_type:
                        mitre_tags = ['TA0002/T1059']
                    elif 'privilege' in vuln_type:
                        mitre_tags = ['TA0004/T1068']

                    cve['mitre_tags'] = mitre_tags

                    # Compliance
                    risk_score = cve['reasoning']['risk_score']
                    sector = infrastructure['sector'].value
                    if sector == 'banking':
                        frameworks = ['PCI-DSS', 'Basel III Cyber']
                    elif sector == 'healthcare':
                        frameworks = ['HIPAA', 'IEC 62443']
                    else:
                        frameworks = ['ISO 27001']

                    cve['compliance'] = {
                        'violation_risk': 'high' if risk_score >= 7 else 'medium',
                        'applicable_frameworks': frameworks
                    }

                progress_bar.progress(75)

                # Step 4: Build attack graph and visualizations
                status_text.text("Building attack graph and visualizations...")

                from graph import TopologyBuilder, AttackPathFinder, TopologyVisualizer
                builder = TopologyBuilder()
                graph = builder.build_graph(infrastructure)

                # Attach CVEs to components
                for cve in relevant_cves:
                    component = cve.get('affected_component')
                    if component and component != 'Unknown':
                        builder.attach_cve_to_component(component, cve)

                # Find attack paths
                finder = AttackPathFinder(graph)
                paths = finder.find_all_attack_paths()

                # Create visualizations
                visualizer = TopologyVisualizer(output_dir="visualizations")

                # Create topology graph
                topology_path = visualizer.create_topology_graph(graph, "topology.html")

                # Create attack path graph
                attack_path_path = visualizer.create_attack_path_graph(graph, paths[:5], "attack_paths.html")

                # Store in session state
                st.session_state.infrastructure = infrastructure
                st.session_state.relevant_cves = relevant_cves
                st.session_state.paths = paths
                st.session_state.topology_graph_path = topology_path
                st.session_state.attack_path_graph_path = attack_path_path
                st.session_state.results_ready = True

                # Clear chat history for new analysis
                if 'chat_history' in st.session_state:
                    st.session_state.chat_history = []
                if 'react_agent' in st.session_state:
                    del st.session_state.react_agent

                progress_bar.progress(100)
                status_text.empty()

                # Show results
                st.success(f"✅ Analysis complete! Found {len(relevant_cves)} CVEs and {len(paths)} attack paths")

            except Exception as e:
                st.error(f"Error: {e}")
                import traceback
                st.code(traceback.format_exc())

    except Exception as e:
        st.error(f"Error: {e}")
        import traceback
        st.code(traceback.format_exc())

# Show results
if st.session_state.results_ready:
    st.markdown("---")
    st.header("Analysis Results")

    # Metrics - cleaner
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("CVEs", len(st.session_state.relevant_cves))
    with col2:
        if st.session_state.relevant_cves:
            avg_risk = sum(cve['reasoning']['risk_score'] for cve in st.session_state.relevant_cves) / len(st.session_state.relevant_cves)
            st.metric("Avg Risk", f"{avg_risk:.1f}", "1-10")
    with col3:
        high_risk = sum(1 for cve in st.session_state.relevant_cves if cve['reasoning']['risk_score'] >= 7)
        st.metric("Critical", high_risk, delta="≥7 risk", delta_color="inverse")
    with col4:
        st.metric("Attack Paths", len(st.session_state.paths))

    # AI Chat - PROMINENT SECTION
    st.markdown("---")
    st.subheader("🤖 AI Security Analyst")

    # Initialize chat history
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    if 'react_agent' not in st.session_state:
        from react_agent import ReActAgent
        st.session_state.react_agent = ReActAgent(
            st.session_state.relevant_cves,
            st.session_state.paths,
            st.session_state.infrastructure
        )

    # Display chat history
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat input
    if prompt := st.chat_input("Ask about vulnerabilities, attack paths, or security posture..."):
        # Add user message
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Get agent response
        with st.chat_message("assistant"):
            with st.spinner("Analyzing..."):
                response = st.session_state.react_agent.chat(prompt)
                st.markdown(response)

        # Add assistant response
        st.session_state.chat_history.append({"role": "assistant", "content": response})

    # Suggested questions - more prominent
    if not st.session_state.chat_history:
        st.markdown("**Quick Questions:**")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button("📊 Get summary"):
                st.session_state.chat_history.append({"role": "user", "content": "Get analysis summary"})
                st.session_state.chat_history.append({"role": "assistant", "content": st.session_state.react_agent.chat("Get analysis summary")})
                st.rerun()
        with col2:
            if st.button("🔴 High-risk CVEs"):
                st.session_state.chat_history.append({"role": "user", "content": "Show high-risk CVEs"})
                st.session_state.chat_history.append({"role": "assistant", "content": st.session_state.react_agent.chat("Show high-risk CVEs")})
                st.rerun()
        with col3:
            if st.button("🕸️ Attack paths"):
                st.session_state.chat_history.append({"role": "user", "content": "Show critical attack paths"})
                st.session_state.chat_history.append({"role": "assistant", "content": st.session_state.react_agent.chat("Show critical attack paths")})
                st.rerun()
        with col4:
            if st.button("🔍 Top vulnerabilities"):
                st.session_state.chat_history.append({"role": "user", "content": "What are my top vulnerabilities?"})
                st.session_state.chat_history.append({"role": "assistant", "content": st.session_state.react_agent.chat("What are my top vulnerabilities?")})
                st.rerun()

    st.markdown("---")

    # Risk Table
    st.subheader("Risk Table")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Risk Distribution**")

        # Count risks by severity
        high_risk = sum(1 for cve in st.session_state.relevant_cves if cve['reasoning']['risk_score'] >= 7)
        medium_risk = sum(1 for cve in st.session_state.relevant_cves if 4 <= cve['reasoning']['risk_score'] < 7)
        low_risk = sum(1 for cve in st.session_state.relevant_cves if cve['reasoning']['risk_score'] < 4)

        # Create pie chart
        fig_risk = go.Figure(data=[go.Pie(
            labels=['High (7-10)', 'Medium (4-6)', 'Low (1-3)'],
            values=[high_risk, medium_risk, low_risk],
            marker=dict(colors=['#ef4444', '#f59e0b', '#22c55e'])
        )])
        fig_risk.update_layout(height=300, margin=dict(l=0, r=0, t=0, b=0), showlegend=True)
        st.plotly_chart(fig_risk, use_container_width=True)

    with col2:
        st.markdown("**Top Vulnerable Components**")

        # Calculate average risk per component
        component_risks = {}
        for cve in st.session_state.relevant_cves:
            component = cve.get('affected_component', 'Unknown')
            risk = cve['reasoning']['risk_score']
            if component not in component_risks:
                component_risks[component] = []
            component_risks[component].append(risk)

        # Average risk per component
        avg_risks = {comp: sum(risks)/len(risks) for comp, risks in component_risks.items()}
        top_components = sorted(avg_risks.items(), key=lambda x: x[1], reverse=True)[:5]

        if top_components:
            components, risks = zip(*top_components)
            fig_comp = go.Figure(data=[go.Bar(
                x=list(risks),
                y=list(components),
                orientation='h',
                marker=dict(color=list(risks), colorscale='Reds')
            )])
            fig_comp.update_layout(height=300, margin=dict(l=0, r=0, t=0, b=0), xaxis_title="Risk Score")
            st.plotly_chart(fig_comp, use_container_width=True)
        else:
            st.info("No component data available")

    # Risk table
    st.subheader("🎯 Risk Table")
    table_data = []
    for cve in st.session_state.relevant_cves:
        reasoning = cve.get('reasoning', {})
        compliance = cve.get('compliance', {})

        # OTX enrichment
        otx_pulse = cve.get('otx_pulse_count', 0)
        otx_active = cve.get('otx_active_exploitation', False)
        otx_indicator = "🔴 ACTIVE" if otx_active else ("⚠️ " + str(otx_pulse) + " pulses" if otx_pulse > 0 else "✅ None")

        table_data.append({
            'CVE ID': cve.get('cve_id'),
            'Component': cve.get('affected_component'),
            'Risk Score': reasoning.get('risk_score', 0),
            'Base Severity': reasoning.get('base_severity', 0),
            'MITRE': cve.get('mitre_tags', [''])[0] if cve.get('mitre_tags') else 'N/A',
            'Compliance': compliance.get('violation_risk', 'unknown'),
            'OTX Threat': otx_indicator,
            'Description': cve.get('description', '')[:80] + '...'
        })

    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True, height=300)

    # Attack Paths & Visualizations
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Attack Paths**")
        for i, path in enumerate(st.session_state.paths[:3], 1):
            route = " → ".join(path["path"])
            risk = path['total_risk']
            st.write(f"**{i}.** {route}")
            st.caption(f"Risk: {risk:.1f}/10")

    with col2:
        st.markdown("**Network Topology**")

        tab1, tab2 = st.tabs(["Topology", "Attack Paths"])

        with tab1:
            if st.session_state.topology_graph_path and os.path.exists(st.session_state.topology_graph_path):
                with open(st.session_state.topology_graph_path, 'r', encoding='utf-8') as f:
                    html_string = f.read()
                st.components.v1.html(html_string, height=300, scrolling=True)

        with tab2:
            if st.session_state.attack_path_graph_path and os.path.exists(st.session_state.attack_path_graph_path):
                with open(st.session_state.attack_path_graph_path, 'r', encoding='utf-8') as f:
                    html_string = f.read()
                st.components.v1.html(html_string, height=300, scrolling=True)

    # Export
    st.markdown("---")

    # Prepare export data
    export_data = {
        'infrastructure': infrastructure,
        'cves': st.session_state.relevant_cves,
        'attack_paths': st.session_state.paths,
        'summary': {
            'total_cves': len(st.session_state.relevant_cves),
            'total_paths': len(st.session_state.paths),
            'high_risk_count': sum(1 for cve in st.session_state.relevant_cves if cve.get('reasoning', {}).get('risk_score', 0) >= 7),
            'timestamp': datetime.now().isoformat()
        }
    }
    json_data = json.dumps(export_data, indent=2, default=str)

    col1, col2 = st.columns(2)
    with col1:
        st.download_button("📥 Download Analysis", json_data, "eaglescout_analysis.json", "application/json")
    with col2:
        csv_data = df.to_csv(index=False)
        st.download_button("📥 Download CSV", csv_data, "eaglescout_analysis.csv", "text/csv")
