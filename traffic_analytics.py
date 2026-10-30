#Using streamlit, pandas and plotly, where pandas handles the summary tables, plotly generates interactive charts, and streamlit displays the interface on the browser.
#To run: py -m streamlit run traffic_analytics.py

from datetime import datetime
import pandas as pd
import plotly.express as px
import psycopg
import streamlit as st


LABEL_SUMMARY_SQL = """
SELECT original_label, COUNT(*) AS flow_count, MIN(observed_at) AS first_seen, MAX(observed_at) AS last_seen
FROM network_flows GROUP BY original_label ORDER BY flow_count DESC, original_label
"""

IMPORT_SUMMARY_SQL = """
SELECT id AS batch_id, source_file, row_count
FROM import_batches ORDER BY id
"""

COLORS = {"Benign": "#0e9e13", "Labeled attack": "#8a0f1b", "Unlabeled": "#474747"}


def prepare_label_summary(records):
    # Calculate percentages 
    frame = pd.DataFrame(
        records, columns=["original_label", "flow_count", "first_seen", "last_seen"]
    )
    if frame.empty:
        frame["traffic_class"] = pd.Series(dtype="str")
        frame["percentage"] = pd.Series(dtype="float64")
        return frame

    frame["flow_count"] = frame["flow_count"].astype("int64")
    # Preserve the source label for inspection and export and normalize only to identify BENIGN as anyother label is an attack category
    labels = frame["original_label"].fillna("").astype(str).str.strip()
    frame["traffic_class"] = labels.map(
        lambda value: "Unlabeled" if not value else
        ("Benign" if value.upper() == "BENIGN" else "Labeled attack")
    )
    total = int(frame["flow_count"].sum())
    frame["percentage"] = frame["flow_count"] * 100.0 / total if total else 0.0
    return frame


def render_overview(labels, imports):
    if labels.empty or int(labels["flow_count"].sum()) == 0:
        st.info("The database is connected, but network_flows contains no traffic yet.")
        return

    total = int(labels["flow_count"].sum())
    classes = labels.groupby("traffic_class", as_index=False)["flow_count"].sum()
    class_counts = classes.set_index("traffic_class")["flow_count"].to_dict()
    benign = int(class_counts.get("Benign", 0))
    attacks = int(class_counts.get("Labeled attack", 0))
    unknown = int(class_counts.get("Unlabeled", 0))

    columns = st.columns(4)
    columns[0].metric("Total flows", f"{total:,}")
    columns[1].metric("Benign flows", f"{benign:,}")
    columns[2].metric("Labeled attack flows", f"{attacks:,}")
    columns[3].metric("Attack share of all flows", f"{attacks / total:.2%}")
    st.caption(
        f"Benign share: {benign / total:.2%}"
    )
    if unknown:
        st.warning(
            f"{unknown:,}. Flows have missing or empty labels. They are shown as "
            "unlabeled and are included in the total, but not counted as attacks."
        )

    st.divider()
    left, right = st.columns([1, 1.5])
    with left:
        st.subheader("Traffic composition")
        figure = px.pie(
            classes, names="traffic_class", values="flow_count", hole=0.68,
            color="traffic_class", color_discrete_map=COLORS,
        )
        figure.update_traces(
            textinfo="percent", textposition="outside",
            hovertemplate="%{label}<br>%{value:,.0f} flows<br>%{percent}<extra></extra>",
        )
        figure.update_layout(
            height=390, margin=dict(l=20, r=20, t=20, b=20),
            legend=dict(orientation="h", y=-0.12, x=0.5, xanchor="center"),
        )
        st.plotly_chart(figure, width="stretch")

    with right:
        st.subheader("Labeled attack categories")
        log_scale = st.checkbox("Use logarithmic count scale", value=False)
        attack_labels = labels.loc[labels["traffic_class"] == "Labeled attack"].copy()
        if attack_labels.empty:
            st.info("There are no attack-labeled flows in this database.")
        else:
            attack_labels["display_label"] = attack_labels["original_label"].astype(str)
            attack_labels = attack_labels.sort_values("flow_count")
            figure = px.bar(
                attack_labels, x="flow_count", y="display_label", orientation="h",
                log_x=log_scale, color_discrete_sequence=[COLORS["Labeled attack"]],
                labels={"flow_count": "Flow records", "display_label": ""},
            )
            figure.update_traces(
                hovertemplate="%{y}<br>%{x:,.0f} labeled flows<extra></extra>"
            )
            figure.update_layout(
                height=max(390, 28 * len(attack_labels) + 80),
                margin=dict(l=10, r=20, t=20, b=30),
                yaxis=dict(categoryorder="array", categoryarray=attack_labels["display_label"].tolist()),
            )
            st.plotly_chart(figure, width="stretch")

    st.subheader("All source labels")
    table = labels[["original_label", "traffic_class", "flow_count", "percentage"]].copy()
    table["original_label"] = table["original_label"].map(
        lambda value: "(missing or empty label)" if pd.isna(value) or not str(value).strip()
        else str(value)
    )
    table.columns = ["Source label", "Traffic class", "Flows", "Share of all flows (%)"]
    st.dataframe(table, hide_index=True, width="stretch")
    st.download_button(
        "Download All source labels (CSV)",
        table.to_csv(index=False).encode("utf-8-sig"),
        file_name="zeng_label_summary.csv", mime="text/csv",
    )

    with st.expander("Imported files and query details"):
        st.dataframe(imports, hide_index=True, width="stretch")


# Only these fixed expressions are used in SQL; filter values use parameters.
TRAFFIC_CLASS_SQL = """CASE
 WHEN original_label IS NULL OR BTRIM(original_label) = '' THEN 'Unlabeled'
 WHEN UPPER(BTRIM(original_label)) = 'BENIGN' THEN 'Benign'
 ELSE 'Labeled attack' END"""
INTERVALS = {"5 minutes": "5 minutes", "15 minutes": "15 minutes", "1 hour": "1 hour", "1 day": "1 day"}
PROTOCOLS = {1: "ICMP (1)", 6: "TCP (6)", 17: "UDP (17)"}


def connect_database(settings):
    connection = psycopg.connect(
        **settings, connect_timeout=10, application_name="zeng_traffic_analytics",
        options="-c statement_timeout=120000",
    )
    connection.read_only = True
    connection.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
    return connection


def load_filter_options(settings):
    with connect_database(settings) as connection, connection.cursor() as cursor:
        cursor.execute(IMPORT_SUMMARY_SQL)
        imports = pd.DataFrame(cursor.fetchall(), columns=["batch_id", "source_file", "row_count"])
        cursor.execute("SELECT DISTINCT protocol FROM network_flows ORDER BY protocol")
        protocols = [row[0] for row in cursor.fetchall() if row[0] is not None]
        cursor.execute("SELECT DISTINCT original_label FROM network_flows ORDER BY original_label")
        labels = [row[0] for row in cursor.fetchall() if row[0] is not None]
        cursor.execute("SELECT MIN(observed_at), MAX(observed_at) FROM network_flows")
        bounds = cursor.fetchone()
    return imports, protocols, labels, bounds


def build_where(filters):
    clauses, parameters = [], []
    for column, key in [("import_batch_id", "batches"), ("protocol", "protocols"), ("original_label", "labels")]:
        if filters[key]:
            clauses.append(f"{column} = ANY(%s)")
            parameters.append(filters[key])
    if filters.get("start") is not None:
        clauses.append("observed_at >= %s")
        parameters.append(filters["start"])
    if filters.get("end") is not None:
        clauses.append("observed_at < %s")
        parameters.append(filters["end"])
    if filters.get("port") is not None:
        clauses.append("destination_port = %s")
        parameters.append(filters["port"])
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), parameters


def load_analytics(settings, filters):
    where, parameters = build_where(filters)
    with connect_database(settings) as connection, connection.cursor() as cursor:
        def query(sql, columns, prefix=()):
            cursor.execute(sql, [*prefix, *parameters])
            return pd.DataFrame(cursor.fetchall(), columns=columns)

        labels = query(
            "SELECT original_label, COUNT(*), MIN(observed_at), MAX(observed_at) FROM network_flows"
            + where + " GROUP BY original_label ORDER BY COUNT(*) DESC, original_label",
            ["original_label", "flow_count", "first_seen", "last_seen"],
        )
        labels = prepare_label_summary(labels.itertuples(index=False, name=None))
        protocols = query(
            f"SELECT protocol, {TRAFFIC_CLASS_SQL} AS traffic_class, COUNT(*) FROM network_flows"
            + where + " GROUP BY protocol, traffic_class ORDER BY COUNT(*) DESC",
            ["protocol", "traffic_class", "flow_count"],
        )
        ports = query(
            "SELECT protocol, destination_port, COUNT(*) AS flows, "
            f"COUNT(*) FILTER (WHERE ({TRAFFIC_CLASS_SQL}) = 'Labeled attack') AS attacks "
            "FROM network_flows" + where
            + " GROUP BY protocol, destination_port ORDER BY flows DESC, protocol, destination_port LIMIT 20",
            ["protocol", "destination_port", "flow_count", "attack_count"],
        )
        connections = query(
            "SELECT source_ip::text, destination_ip::text, protocol, destination_port, COUNT(*) AS flows, "
            f"COUNT(*) FILTER (WHERE ({TRAFFIC_CLASS_SQL}) = 'Labeled attack'), "
            "MIN(observed_at), MAX(observed_at) FROM network_flows" + where
            + " GROUP BY source_ip, destination_ip, protocol, destination_port "
            "ORDER BY flows DESC, source_ip, destination_ip, protocol, destination_port LIMIT 200",
            ["source_ip", "destination_ip", "protocol", "destination_port", "flow_count", "attack_count", "first_seen", "last_seen"],
        )
        timeline = query(
            "SELECT date_bin(%s::interval, observed_at, TIMESTAMP '2000-01-01') AS time_bucket, "
            f"{TRAFFIC_CLASS_SQL} AS traffic_class, COUNT(*) FROM network_flows" + where
            + (" AND " if where else " WHERE ") + "observed_at IS NOT NULL "
            "GROUP BY time_bucket, traffic_class ORDER BY time_bucket, traffic_class",
            ["time_bucket", "traffic_class", "flow_count"], [INTERVALS[filters["interval"]]],
        )
        # Separate categories retain the original dataset attack names.
        attack_timeline = query(
            "SELECT date_bin(%s::interval, observed_at, TIMESTAMP '2000-01-01') AS time_bucket, "
            "original_label, COUNT(*) FROM network_flows" + where
            + (" AND " if where else " WHERE ")
            + f"observed_at IS NOT NULL AND ({TRAFFIC_CLASS_SQL}) = 'Labeled attack' "
            "GROUP BY time_bucket, original_label ORDER BY time_bucket, original_label",
            ["time_bucket", "original_label", "flow_count"], [INTERVALS[filters["interval"]]],
        )
    return dict(labels=labels, protocols=protocols, ports=ports, connections=connections,
                timeline=timeline, attack_timeline=attack_timeline)


def protocol_name(value):
    return "Unknown" if pd.isna(value) else PROTOCOLS.get(int(value), f"Protocol {int(value)}")


def export_table(frame, filename):
    st.dataframe(frame, hide_index=True, width="stretch")
    st.download_button("Download CSV", frame.to_csv(index=False).encode("utf-8-sig"),
                       file_name=filename, mime="text/csv", key=filename)


def render_connections(result):
    st.subheader("Traffic by protocol")
    protocols = result["protocols"].copy()
    if protocols.empty:
        st.info("No flows match the applied filters.")
        return
    protocols["protocol_name"] = protocols["protocol"].map(protocol_name)
    st.plotly_chart(px.bar(protocols, x="protocol_name", y="flow_count", color="traffic_class",
                          color_discrete_map=COLORS, labels={"protocol_name": "Protocol", "flow_count": "Flows"}), width="stretch")
    st.subheader("Top 20 destination ports by flow count")
    ports = result["ports"].copy()
    ports["connection_type"] = ports.apply(lambda row: f"{protocol_name(row['protocol'])} / port {int(row['destination_port']) if pd.notna(row['destination_port']) else 'unknown'}", axis=1)
    st.caption("Transport protocol and destination port grouped.")
    st.plotly_chart(px.bar(ports, x="flow_count", y="connection_type", orientation="h",
                          color_discrete_sequence=[COLORS["Benign"]],
                          hover_data=["attack_count"], labels={"flow_count": "Flows", "connection_type": ""})
                    .update_layout(yaxis=dict(autorange="reversed")), width="stretch")
    export_table(ports, "zeng_port_summary.csv")
    st.subheader("Top 200 communication patterns")
    st.caption("Grouped by protocol and destination port. Source ports are combined.")
    frame = result["connections"].copy()
    export_table(frame, "zeng_connection_patterns.csv")


def render_time(result, interval):
    st.subheader("Traffic over time")
    timeline = result["timeline"]
    if timeline.empty:
        st.info("No timestamped flows match the applied filters.")
        return
    # Reindex empty buckets to prevent lines bridging unrecorded periods.
    for frame, category, title in [
        (timeline, "traffic_class", "Benign and labeled attack traffic"),
        (result["attack_timeline"], "original_label", "Labeled attack categories over time"),
    ]:
        st.write(title)
        if frame.empty:
            st.info("No labeled attacks in the selected traffic.")
            continue
        grid = pd.date_range(timeline.time_bucket.min(), timeline.time_bucket.max(),
                             freq={"5 minutes": "5min", "15 minutes": "15min", "1 hour": "1h", "1 day": "1D"}[interval])
        wide = frame.pivot(index="time_bucket", columns=category, values="flow_count").reindex(grid).fillna(0)
        wide.index.name = "time_bucket"
        chart = wide.reset_index().melt(id_vars="time_bucket", var_name=category, value_name="flow_count")
        st.plotly_chart(px.line(chart, x="time_bucket", y="flow_count", color=category,
                               color_discrete_map=COLORS if category == "traffic_class" else None,
                               labels={"time_bucket": "Recorded time", "flow_count": "Flows"}), width="stretch")
    export_table(timeline, "zeng_traffic_timeline.csv")


def main():
    st.set_page_config(page_title="Network Traffic Overview", page_icon="Z")
    st.caption("Z-ENG: Network Intrusion Detection and Security Analytics Dashboard")
    st.title("Network Traffic Overview")
    with st.sidebar:
        st.header("Connect to the Database")
        with st.form("database_connection"):
            host = st.text_input("Host", value="localhost")
            port = st.number_input("Port", min_value=1, max_value=65535, value=5432)
            database = st.text_input("Database name", value="zeng_security")
            username = st.text_input("Username", value="postgres")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Connect")
    if submitted:
        for key in ["analytics_result", "filter_options", "db_settings", "applied_filters"]:
            st.session_state.pop(key, None)
        settings = dict(host=host, port=int(port), dbname=database, user=username, password=password)
        try:
            with st.spinner("Reading database filters..."):
                options = load_filter_options(settings)
            st.session_state["db_settings"] = settings
            st.session_state["filter_options"] = options
        except psycopg.Error:
            st.error("Could not read the database. Check the connection details, schema, and PostgreSQL server.")
    if "db_settings" not in st.session_state:
        st.write("Enter your database connection details in the sidebar, then click **Connect**.")
        return
    imports, protocols, labels, bounds = st.session_state["filter_options"]
    with st.sidebar:
        st.header("Traffic filters")
        st.caption("Empty selections include all values. Apply filters to update every view.")
        with st.form("traffic_filters"):
            names = dict(zip(imports.batch_id, imports.source_file))
            batches = st.multiselect("Imported files", imports.batch_id.tolist(), format_func=lambda x: f"{x}: {names[x]}")
            selected_protocols = st.multiselect("Protocols", protocols, format_func=protocol_name)
            selected_labels = st.multiselect("Source labels", labels)
            limit_port = st.checkbox("Filter destination port")
            destination_port = st.number_input("Destination port", 0, 65535, 443)
            limit_time = st.checkbox("Filter recorded time")
            minimum, maximum = bounds
            fallback = datetime(2017, 7, 3)
            start = st.text_input("Start (inclusive)", value=str(minimum or fallback), help="YYYY-MM-DD HH:MM:SS")
            end = st.text_input("End (exclusive)", value=str((maximum + pd.Timedelta(seconds=1)) if maximum else fallback), help="YYYY-MM-DD HH:MM:SS")
            interval = st.selectbox("Time interval", list(INTERVALS), index=2)
            apply = st.form_submit_button("Apply filters / refresh")
    if apply or "analytics_result" not in st.session_state:
        try:
            start_value = datetime.fromisoformat(start) if limit_time else None
            end_value = datetime.fromisoformat(end) if limit_time else None
            if limit_time and (start_value.tzinfo is not None or end_value.tzinfo is not None or start_value >= end_value):
                raise ValueError("Use a start earlier than the end, with no time-zone offset.")
        except ValueError:
            st.error("Enter valid timestamps (YYYY-MM-DD HH:MM:SS), with start before end and no time-zone offset.")
            return
        filters = dict(batches=batches, protocols=selected_protocols, labels=selected_labels,
                       port=int(destination_port) if limit_port else None,
                       start=start_value, end=end_value, interval=interval)
        try:
            with st.spinner("Calculating filtered summaries in PostgreSQL..."):
                result = load_analytics(st.session_state["db_settings"], filters)
            st.session_state["analytics_result"] = result
            st.session_state["applied_filters"] = filters
            st.session_state["loaded_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except psycopg.Error:
            st.error("The analytics query failed or exceeded 120 seconds. Check the database and try a smaller selection.")
            return
    result = st.session_state["analytics_result"]
    applied = st.session_state["applied_filters"]
    settings = st.session_state["db_settings"]
    st.caption(f"Database source: {settings['dbname']} on {settings['host']}:{settings['port']} · Loaded {st.session_state['loaded_at']}")
    with st.expander("Applied filters", expanded=False):
        st.write({k: str(v) for k, v in applied.items()})
    overview, connections, time = st.tabs(["Overview", "Protocols & connections", "Time analysis"])
    with overview:
        render_overview(result["labels"], imports)
    with connections:
        render_connections(result)
    with time:
        render_time(result, applied["interval"])


if __name__ == "__main__":


    main()
