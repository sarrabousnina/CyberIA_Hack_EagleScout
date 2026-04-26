"""Custom UI helpers for EagleScout cybersecurity theme."""

import streamlit as st


def alert(msg: str, kind: str = "info"):
    """
    Custom alert component with glowing hint card style.

    Args:
        msg: Alert message
        kind: Type of alert (success, error, warning, info)
    """
    # For the glowing hint card, we only use this for info kind
    if kind == "info":
        return st.markdown(f"""
        <div style="background: linear-gradient(135deg, rgba(0, 194, 203, 0.12), rgba(2, 128, 144, 0.08));
                    border: 1px solid rgba(0, 194, 203, 0.3);
                    border-radius: 12px;
                    padding: 1.2rem 1.5rem;
                    margin: 0.5rem 0; color:#2c3e50;">
            {msg}
        </div>""", unsafe_allow_html=True)

    # For other alert types, use traditional style
    border_colors = {
        "success": "#2ED573",
        "error": "#FF4757",
        "warning": "#FFA502",
        "info": "#00C2CB",
    }

    bg_colors = {
        "success": "rgba(46, 213, 115, 0.12)",
        "error": "rgba(255, 71, 87, 0.12)",
        "warning": "rgba(255, 165, 2, 0.12)",
        "info": "rgba(0, 194, 203, 0.12)",
    }

    border_c = border_colors.get(kind, "#00C2CB")
    bg_c = bg_colors.get(kind, bg_colors["info"])

    return st.markdown(f"""
    <div style="background:{bg_c}; border-left:4px solid {border_c};
                padding:0.85rem 1.2rem; border-radius:8px;
                margin:0.5rem 0; color:#2c3e50; font-size:0.95rem;
                backdrop-filter:blur(10px); animation:slideIn 0.3s ease-out;">
        {msg}
    </div>""", unsafe_allow_html=True)


def section_header(label: str, title: str):
    """
    Custom section header with label and title.

    Args:
        label: Small label above title (e.g., "ANALYSIS", "RESULTS")
        title: Main section title
    """
    st.markdown(f"""
    <div style="margin:2rem 0 1rem 0;">
        <div style="color:#00C2CB; font-size:0.7rem; font-weight:700;
                    letter-spacing:0.15em; text-transform:uppercase;
                    margin-bottom:0.3rem;">{label}</div>
        <div style="color:#2c3e50; font-size:1.6rem; font-weight:700;
                    line-height:1.2;">{title}</div>
        <div style="height:1px; background:rgba(0, 194, 203, 0.2); margin-top:0.75rem;"></div>
    </div>""", unsafe_allow_html=True)


def metric_pills(items: dict):
    """
    Display metrics as color-coded pills with subtle backgrounds.

    Args:
        items: Dictionary of metric names and values
    """
    # Color mapping by metric type
    colors = {
        "CVEs": "#00C2CB",  # teal
        "Attack Paths": "#FFA502",  # orange
        "Critical CVEs": "#FF4757",  # red
    }

    pills = ""
    for k, v in items.items():
        # Determine color based on metric name
        if "Avg Risk" in k:
            # Dynamic color based on value
            try:
                val = float(str(v).split('/')[0])
                if val < 5:
                    color = "#2ED573"  # green
                elif val < 7:
                    color = "#FFA502"  # orange
                else:
                    color = "#FF4757"  # red
            except:
                color = "#FFA502"
        else:
            color = colors.get(k, "#00C2CB")

        # Convert color to 12% opacity for background (lighter for light theme)
        bg_color = color + "1F"  # Add alpha (12% in hex is 1F)

        pills += f'<span style="background:{bg_color};color:{color}; ' \
                    f'border:1px solid {color}; ' \
                    f'border-radius:20px; padding:0.4rem 1rem; ' \
                    f'font-weight:700; margin-right:0.75rem; ' \
                    f'display:inline-block; transition:all 0.3s ease; ' \
                    f'box-shadow: 0 2px 8px rgba(0,0,0,0.08);">' \
                    f'{k}: <strong>{v}</strong></span>'

    st.markdown(f'<div style="margin:0.75rem 0;">{pills}</div>', unsafe_allow_html=True)


def terminal_log(lines: list):
    """
    Display terminal-style log output with subtle transparent background.

    Args:
        lines: List of log lines to display
    """
    rows = "".join([
        f'<div><span style="color:#00C2CB;">❯</span> '
        f'<span style="color:#2c3e50;">{line}</span></div>'
        for line in lines
    ])
    st.markdown(f"""
    <div style="background:rgba(255, 255, 255, 0.6);
                border:1px solid rgba(0, 194, 203, 0.2); border-radius:8px;
                padding:1rem 1.2rem; font-family:monospace; font-size:0.85rem;
                line-height:1.8; margin:0.75rem 0; backdrop-filter:blur(5px);
                animation:slideIn 0.3s ease-out;">
        {rows}
    </div>""", unsafe_allow_html=True)


def attack_path_card(index: int, path: str, risk: float):
    """
    Display an attack path as a styled card with subtle transparent background.

    Args:
        index: Path number
        path: Attack path string (e.g., "internet → nginx → postgres)
        risk: Risk score (1-10)
    """
    risk_color = "#FF4757" if risk >= 8 else "#FFA502" if risk >= 5 else "#2ED573"
    risk_gradient = {
        "#FF4757": "linear-gradient(135deg, #FF4757 0%, #FF6B7A 100%)",
        "#FFA502": "linear-gradient(135deg, #FFA502 0%, #FFB733 100%)",
        "#2ED573": "linear-gradient(135deg, #2ED573 0%, #5CDB95 100%)"
    }

    gradient = risk_gradient.get(risk_color, risk_gradient["#2ED573"])
    nodes = " <span style='color:#00C2CB;'>→</span> ".join(path.split(" → "))

    st.markdown(f"""
    <div style="background:rgba(255, 255, 255, 0.7);
                border-left:4px solid {risk_color};
                border-radius:8px; padding:1rem 1.2rem; margin:0.6rem 0;
                display:flex; justify-content:space-between; align-items:flex-start;
                backdrop-filter:blur(10px); animation:slideIn 0.5s ease-out;
                transition:all 0.3s ease; border:1px solid rgba(0, 194, 203, 0.15);
                box-shadow: 0 2px 8px rgba(0,0,0,0.06);">
        <div>
            <div style="color:#7a8c9d; font-size:0.75rem; margin-bottom:0.3rem; font-weight:600;">
                PATH {index}
            </div>
            <div style="color:#2c3e50; font-size:0.95rem; font-weight:500;">{nodes}</div>
        </div>
        <div style="background:{gradient}; color:#FFFFFF;
                    border-radius:6px; padding:0.3rem 0.8rem; font-size:0.8rem;
                    font-weight:700; white-space:nowrap; margin-left:1rem;
                    box-shadow:0 2px 8px rgba(0,0,0,0.15);">
            RISK {risk}/10
        </div>
    </div>""", unsafe_allow_html=True)


def risk_table_html(df):
    """
    Generate HTML for styled risk table with transparent backgrounds and scrollable container.

    Args:
        df: Pandas DataFrame with CVE data

    Returns:
        HTML string for the table
    """
    def score_badge(score):
        if score >= 8:
            c = "#FF4757"
            g = "linear-gradient(135deg, #FF4757 0%, #FF6B7A 100%)"
        elif score >= 5:
            c = "#FFA502"
            g = "linear-gradient(135deg, #FFA502 0%, #FFB733 100%)"
        else:
            c = "#2ED573"
            g = "linear-gradient(135deg, #2ED573 0%, #5CDB95 100%)"
        return f'<span style="background:{g};color:#FFFFFF;border:1px solid {c};border-radius:6px;padding:3px 10px;font-weight:700;box-shadow:0 2px 4px rgba(0,0,0,0.15);">{score}</span>'

    def mitre_chip(tag):
        return f'<span style="background:rgba(0, 194, 203, 0.12);color:#00C2CB;border:1px solid rgba(0, 194, 203, 0.3);border-radius:4px;padding:3px 8px;font-size:0.8rem;font-family:monospace;">{tag}</span>'

    rows = ""
    for i, row in df.iterrows():
        bg = "rgba(255, 255, 255, 0.5)" if i % 2 == 0 else "rgba(245, 240, 232, 0.5)"
        rows += f"""<tr style="background:{bg};transition:all 0.2s ease;">
            <td style="padding:12px 14px;color:#7a8c9d;font-size:0.8rem;">{i+1}</td>
            <td style="padding:12px 14px;color:#00C2CB;font-family:monospace;font-size:0.85rem;font-weight:600;">{row.get('CVE ID','')}</td>
            <td style="padding:12px 14px;color:#2c3e50;">{row.get('Component','')}</td>
            <td style="padding:12px 14px;">{score_badge(row.get('Risk Score',0))}</td>
            <td style="padding:12px 14px;color:#2c3e50;">{row.get('Base Severity','')}</td>
            <td style="padding:12px 14px;">{mitre_chip(row.get('MITRE',''))}</td>
            <td style="padding:12px 14px;color:#2c3e50;">{row.get('Compliance','')}</td>
            <td style="padding:12px 14px;color:#7a8c9d;font-size:0.82rem;">{str(row.get('Description',''))[:80]}...</td>
        </tr>"""

    return f"""
    <div style="max-height:500px;overflow-y:auto;border-radius:12px;border:1px solid rgba(0, 194, 203, 0.2);box-shadow:0 4px 20px rgba(0,0,0,0.08);">
    <table style="width:100%;border-collapse:collapse;background:transparent;">
        <thead style="position:sticky;top:0;z-index:10;">
            <tr style="background:rgba(245, 240, 232, 0.95);border-bottom:2px solid #00C2CB;">
                <th style="padding:14px;color:#00C2CB;font-size:0.75rem;letter-spacing:0.15em;text-align:left;text-transform:uppercase;">#</th>
                <th style="padding:14px;color:#00C2CB;font-size:0.75rem;letter-spacing:0.15em;text-align:left;text-transform:uppercase;">CVE ID</th>
                <th style="padding:14px;color:#00C2CB;font-size:0.75rem;letter-spacing:0.15em;text-align:left;text-transform:uppercase;">Component</th>
                <th style="padding:14px;color:#00C2CB;font-size:0.75rem;letter-spacing:0.15em;text-align:left;text-transform:uppercase;">Risk</th>
                <th style="padding:14px;color:#00C2CB;font-size:0.75rem;letter-spacing:0.15em;text-align:left;text-transform:uppercase;">Severity</th>
                <th style="padding:14px;color:#00C2CB;font-size:0.75rem;letter-spacing:0.15em;text-align:left;text-transform:uppercase;">Mitre</th>
                <th style="padding:14px;color:#00C2CB;font-size:0.75rem;letter-spacing:0.15em;text-align:left;text-transform:uppercase;">Compliance</th>
                <th style="padding:14px;color:#00C2CB;font-size:0.75rem;letter-spacing:0.15em;text-align:left;text-transform:uppercase;">Description</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table></div>"""
