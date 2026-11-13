"""Dashboard Streamlit de supervision AIOps — Étape 5 du TP5.

Cette interface permet de visualiser en temps réel :
- L'état global de l'infrastructure DemoTech et le nombre d'incidents.
- La supervision réseau (graphique interactif de la latence, statuts, ports).
- La supervision de la sécurité (tableaux des alertes et événements suspects).
- La supervision système (graphiques d'évolution CPU, RAM et disque par serveur).
- La supervision applicative (erreurs classifiées et journaux d'application).
- Les recommandations consolidées produites par les agents et enrichies par l'IA.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ajouter la racine du projet dans sys.path pour les imports des agents et de l'orchestrateur
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from orchestration.orchestrator import load_orchestrator_data, infrastructure_orchestrator

# Configuration de la page Streamlit
st.set_page_config(
    page_title="AIOps - Infrastructure Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DATASETS_DIR = ROOT_DIR / "datasets"
OUTPUTS_DIR = ROOT_DIR / "outputs"
ORCHESTRATOR_OUTPUT_FILE = OUTPUTS_DIR / "orchestrator_results.json"


@st.cache_data(ttl=60)
def get_orchestrator_results():
    """Charge ou exécute l'orchestration multi-agents pour alimenter le dashboard."""
    if ORCHESTRATOR_OUTPUT_FILE.exists():
        try:
            with open(ORCHESTRATOR_OUTPUT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # Si le fichier n'est pas encore généré, exécuter directement l'orchestrateur
    data, config = load_orchestrator_data()
    results = infrastructure_orchestrator(data, config)
    with open(ORCHESTRATOR_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    return results


@st.cache_data
def load_raw_data():
    """Charge les données brutes pour les visualisations interactives détaillées."""
    net_df = pd.read_csv(DATASETS_DIR / "network_logs.csv")
    net_df["timestamp"] = pd.to_datetime(net_df["timestamp"])

    sec_df = pd.read_csv(DATASETS_DIR / "security_logs.csv")
    sec_df["timestamp"] = pd.to_datetime(sec_df["timestamp"])

    sys_df = pd.read_csv(DATASETS_DIR / "system_metrics.csv")
    sys_df["timestamp"] = pd.to_datetime(sys_df["timestamp"])

    with open(DATASETS_DIR / "application_logs.txt", "r", encoding="utf-8") as f:
        app_lines = [l.strip() for l in f if l.strip()]

    with open(DATASETS_DIR / "infrastructure_config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    return net_df, sec_df, sys_df, app_lines, config


# Chargement des résultats
results = get_orchestrator_results()
net_df, sec_df, sys_df, app_lines, config = load_raw_data()

# ==========================================
# HEADER & TITRE PRINCIPAL
# ==========================================
st.title("AIOps — Infrastructure Monitoring")
st.caption("Plateforme intelligente de supervision, administration et cybersécurité multi-agents | DemoTech")

# Sidebar : Filtres et contrôles
st.sidebar.image("https://img.icons8.com/color/96/server.png", width=70)
st.sidebar.title("Centre de Contrôle")
st.sidebar.markdown("**Environnement :** `DemoTech Training Lab`")

if st.sidebar.button("🔄 Rafraîchir l'analyse des agents"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("### Agents Spécialisés Actifs")
st.sidebar.success("🟢 Network Agent")
st.sidebar.success("🟢 Security Agent")
st.sidebar.success("🟢 System Agent")
st.sidebar.success("🟢 Application Agent")
st.sidebar.info("🤖 Orchestrator + LLM Module")

# ==========================================
# 1. INFRASTRUCTURE STATUS
# ==========================================
st.header("Infrastructure Status")

global_status_data = results.get("global_status", {})
current_status = global_status_data.get("status", "UNKNOWN")
reason = global_status_data.get("reason", "Aucune information.")
total_alerts = global_status_data.get("total_alerts_count", 0)
critical_alerts = global_status_data.get("critical_alerts_count", 0)
high_alerts = global_status_data.get("high_alerts_count", 0)

# Cartes métriques
col_status, col_incidents, col_crit, col_high = st.columns(4)

with col_status:
    if current_status == "CRITICAL":
        st.error(f"### État : CRITIQUE\n**{current_status}**")
    elif current_status == "DEGRADED":
        st.warning(f"### État : DÉGRADÉ\n**{current_status}**")
    else:
        st.success(f"### État : OPÉRATIONNEL\n**{current_status}**")

with col_incidents:
    st.metric("Total des alertes consolidées", total_alerts)

with col_crit:
    st.metric("Alertes Critiques", critical_alerts, delta="Urgent" if critical_alerts > 0 else "0", delta_color="inverse")

with col_high:
    st.metric("Alertes Sévérité Haute", high_alerts)

st.info(f"**Diagnostic Global de l'Orchestrateur :** {reason}")

# Vue des incidents corrélés multi-agents
cross_analysis = results.get("cross_incident_analysis", {})
incidents_list = cross_analysis.get("incidents", [])

if incidents_list:
    with st.expander(f"🔍 Voir les {len(incidents_list)} incidents transversaux corrélés détectés", expanded=True):
        for inc in incidents_list:
            sev_badge = "🔴 CRITIQUE" if inc.get("severity") == "CRITICAL" else "🟠 ÉLEVÉ"
            st.markdown(f"#### {sev_badge} — {inc.get('title')}")
            st.markdown(f"**Période :** `{inc.get('time_window')}` | **Composants :** {inc.get('affected_components')}")
            st.markdown(f"**Hypothèse causale :** {inc.get('explanatory_hypothesis')}")
            st.markdown(f"*{inc.get('correlation_vs_causality')}*")
            st.markdown("---")

# ==========================================
# 2. NETWORK MONITORING
# ==========================================
st.header("Network Monitoring")

net_stats = results.get("network", {})
mean_latency = net_stats.get("mean_latency_ms", net_df["latency_ms"].mean())
fail_rate = net_stats.get("failure_rate_percent", 0.0)
failed_comms = net_stats.get("failed_communications", 0)

col_net1, col_net2, col_net3, col_net4 = st.columns(4)
col_net1.metric("Latence moyenne", f"{mean_latency:.1f} ms")
col_net2.metric("Taux d'échec", f"{fail_rate:.2f} %")
col_net3.metric("Communications en échec (FAILED)", failed_comms)
col_net4.metric("Communications lentes (SLOW)", (net_df["status"] == "SLOW").sum())

# Graphique interactif Plotly de la latence
latency_threshold = config.get("thresholds", {}).get("latency_ms", 150)
fig_lat = px.line(
    net_df.sort_values("timestamp"),
    x="timestamp",
    y="latency_ms",
    color="status",
    color_discrete_map={"OK": "#2ca02c", "SLOW": "#ff7f0e", "FAILED": "#d62728"},
    title="Évolution temporelle de la latence réseau (ms)",
    labels={"timestamp": "Horodatage", "latency_ms": "Latence (ms)", "status": "Statut"},
)
fig_lat.add_hline(
    y=latency_threshold,
    line_dash="dash",
    line_color="red",
    annotation_text=f"Seuil critique ({latency_threshold} ms)",
    annotation_position="top left",
)
fig_lat.update_layout(height=400, margin=dict(l=20, r=20, t=40, b=20))
st.plotly_chart(fig_lat, use_container_width=True)

# Répartition par port et alertes réseau
col_port_chart, col_net_alerts = st.columns([1, 1])

with col_port_chart:
    st.subheader("Répartition des requêtes par port")
    port_counts = net_df["port"].value_counts().reset_index()
    port_counts.columns = ["port", "count"]
    port_names = {80: "HTTP (80)", 443: "HTTPS (443)", 53: "DNS (53)", 5432: "PostgreSQL (5432)"}
    port_counts["service"] = port_counts["port"].map(port_names)
    fig_port = px.pie(
        port_counts,
        names="service",
        values="count",
        hole=0.4,
        color_discrete_sequence=px.colors.qualitative.Pastel,
    )
    fig_port.update_layout(height=280, margin=dict(l=10, r=10, t=20, b=20))
    st.plotly_chart(fig_port, use_container_width=True)

with col_net_alerts:
    st.subheader("Alertes de l'Agent Réseau")
    alerts_net = net_stats.get("alerts", [])
    if alerts_net:
        for al in alerts_net:
            st.error(f"⚠️ {al}")
    else:
        st.success("Aucune anomalie réseau détectée.")

# ==========================================
# 3. SECURITY MONITORING
# ==========================================
st.header("Security Monitoring")

sec_col1, sec_col2 = st.columns([1, 1])

with sec_col1:
    st.subheader("Alertes de Sécurité Qualifiées")
    sec_alerts = results.get("security", [])
    if sec_alerts:
        for al in sec_alerts:
            sev = al.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                st.error(f"🚨 **{al.get('type')}** ({sev})\n\n{al.get('message')}\n\n*Recommandation : {al.get('recommendation')}*")
            else:
                st.warning(f"⚠️ **{al.get('type')}** ({sev})\n\n{al.get('message')}\n\n*Recommandation : {al.get('recommendation')}*")
    else:
        st.success("Aucune alerte de sécurité active.")

with sec_col2:
    st.subheader("Répartition des événements par criticité")
    sev_counts = sec_df["severity"].value_counts().reset_index()
    sev_counts.columns = ["severity", "count"]
    fig_sec = px.bar(
        sev_counts,
        x="severity",
        y="count",
        color="severity",
        color_discrete_map={"INFO": "#1f77b4", "LOW": "#2ca02c", "MEDIUM": "#ff7f0e", "HIGH": "#d62728", "CRITICAL": "#7f0000"},
    )
    fig_sec.update_layout(height=280, margin=dict(l=20, r=20, t=30, b=20), showlegend=False)
    st.plotly_chart(fig_sec, use_container_width=True)

st.subheader("Tableau des Événements de Sécurité Suspects")
sec_filter = st.selectbox(
    "Filtrer par sévérité :",
    ["TOUS", "HIGH", "CRITICAL", "LOW", "INFO"],
    index=0,
)
if sec_filter == "TOUS":
    st.dataframe(sec_df.sort_values("timestamp", ascending=False), use_container_width=True, height=220)
else:
    st.dataframe(sec_df[sec_df["severity"] == sec_filter].sort_values("timestamp", ascending=False), use_container_width=True, height=220)

# ==========================================
# 4. SYSTEM MONITORING
# ==========================================
st.header("System Monitoring")

sys_thresh = config.get("thresholds", {})
cpu_t = sys_thresh.get("cpu", 80)
mem_t = sys_thresh.get("memory", 85)
disk_t = sys_thresh.get("disk", 90)

col_sys_m1, col_sys_m2, col_sys_m3 = st.columns(3)
col_sys_m1.metric("Pic CPU enregistré", f"{sys_df['cpu_usage'].max():.1f} %", delta=f"Seuil: {cpu_t}%", delta_color="inverse")
col_sys_m2.metric("Pic Mémoire enregistré", f"{sys_df['memory_usage'].max():.1f} %", delta=f"Seuil: {mem_t}%", delta_color="inverse")
col_sys_m3.metric("Pic Disque enregistré", f"{sys_df['disk_usage'].max():.1f} %", delta=f"Seuil: {disk_t}%", delta_color="inverse")

# Graphique de l'évolution CPU et Mémoire
col_cpu_g, col_mem_g = st.columns(2)

with col_cpu_g:
    fig_cpu = px.line(
        sys_df.sort_values("timestamp"),
        x="timestamp",
        y="cpu_usage",
        color="hostname",
        title="Utilisation CPU par serveur (%)",
        labels={"timestamp": "Horodatage", "cpu_usage": "CPU (%)", "hostname": "Serveur"},
    )
    fig_cpu.add_hline(y=cpu_t, line_dash="dash", line_color="red", annotation_text=f"Seuil CPU ({cpu_t}%)")
    fig_cpu.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20))
    st.plotly_chart(fig_cpu, use_container_width=True)

with col_mem_g:
    fig_mem = px.line(
        sys_df.sort_values("timestamp"),
        x="timestamp",
        y="memory_usage",
        color="hostname",
        title="Utilisation Mémoire par serveur (%)",
        labels={"timestamp": "Horodatage", "memory_usage": "Mémoire (%)", "hostname": "Serveur"},
    )
    fig_mem.add_hline(y=mem_t, line_dash="dash", line_color="orange", annotation_text=f"Seuil RAM ({mem_t}%)")
    fig_mem.update_layout(height=350, margin=dict(l=20, r=20, t=40, b=20))
    st.plotly_chart(fig_mem, use_container_width=True)

# Alertes système générées
st.subheader("Alertes de dépassement de ressources (System Agent)")
sys_alerts = results.get("system", [])
if sys_alerts:
    sys_alerts_df = pd.DataFrame(sys_alerts)[
        ["hostname", "type", "severity", "maximum_value_percent", "threshold_percent", "exceeded_measurement_count", "first_detection", "last_detection", "recommendation"]
    ]
    st.dataframe(sys_alerts_df, use_container_width=True)
else:
    st.success("Toutes les métriques serveurs sont sous les seuils d'alerte.")

# ==========================================
# 5. APPLICATION MONITORING
# ==========================================
st.header("Application Monitoring")

app_res = results.get("application", {})
errors_list = app_res.get("errors", [])
warnings_list = app_res.get("warnings", [])
recurring_errs = app_res.get("recurring_errors", {})

col_app1, col_app2, col_app3 = st.columns(3)
col_app1.metric("Total événements analysés", len(app_lines))
col_app2.metric("Erreurs applicatives (ERROR)", len(errors_list), delta="Anomalies" if errors_list else "0", delta_color="inverse")
col_app3.metric("Avertissements (WARNING)", len(warnings_list))

col_app_t1, col_app_t2 = st.columns([1, 1])

with col_app_t1:
    st.subheader("Fréquence des erreurs applicatives récurrentes")
    if recurring_errs:
        err_df = pd.DataFrame(list(recurring_errs.items()), columns=["Message", "Occurrences"])
        fig_err = px.bar(
            err_df.sort_values("Occurrences", ascending=True),
            x="Occurrences",
            y="Message",
            orientation="h",
            color="Occurrences",
            color_continuous_scale="Reds",
        )
        fig_err.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig_err, use_container_width=True)
    else:
        st.info("Aucune erreur récurrente.")

with col_app_t2:
    st.subheader("Concentration horaire des erreurs")
    conc_periods = app_res.get("error_concentration_periods", {})
    if conc_periods:
        conc_df = pd.DataFrame(list(conc_periods.items()), columns=["Plage horaire", "Nombre d'erreurs"])
        fig_conc = px.bar(
            conc_df,
            x="Plage horaire",
            y="Nombre d'erreurs",
            color="Nombre d'erreurs",
            color_continuous_scale="Sunsetdark",
        )
        fig_conc.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig_conc, use_container_width=True)
    else:
        st.info("Erreurs réparties uniformément.")

# Tableau des dernières erreurs
st.subheader("Tableau des Erreurs Applicatives Récentes")
if errors_list:
    st.dataframe(pd.DataFrame(errors_list).sort_values("timestamp", ascending=False), use_container_width=True, height=220)
else:
    st.success("Aucune erreur applicative enregistrée.")

# ==========================================
# 6. AI RECOMMENDATIONS
# ==========================================
st.header("AI Recommendations")

llm_data = results.get("llm_interpretation", {})
if llm_data and llm_data.get("status") == "SUCCESS":
    st.success(f"🤖 **Interprétation IA générée par :** `{llm_data.get('model')}`")

    st.markdown("### Résumé de la situation (LLM)")
    st.info(llm_data.get("situation_summary"))

    st.markdown("### Explication globale des causes")
    st.write(llm_data.get("clear_explanation"))

    col_rec_p, col_rec_v = st.columns([1.2, 1])

    with col_rec_p:
        st.markdown("### Plan d'Actions Recommandé")
        for rec in llm_data.get("recommendations", []):
            st.markdown(
                f"- **[{rec.get('priority')}] {rec.get('target')} :** {rec.get('action')}"
            )

    with col_rec_v:
        st.markdown("### ⚠️ Éléments Nécessitant Validation Humaine")
        for h_item in llm_data.get("human_verification_required", []):
            st.warning(f"🔒 {h_item}")
else:
    # Fallback sur les recommandations des agents si LLM non disponible
    general_recs = results.get("recommendations", [])
    if general_recs:
        for r in general_recs:
            st.markdown(f"- **{r.get('source')} :** {r.get('recommendation')}")
    else:
        st.info("Aucune recommandation particulière.")

st.markdown("---")
st.caption("AIOps Multi-Agent Platform © 2026 - Master / CI GI - FST Settat")

