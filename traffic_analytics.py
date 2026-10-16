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


def load_summaries(host, port, database, username, password):
    with psycopg.connect(
        host=host, port=port, dbname=database, user=username, password=password,
        connect_timeout=10, application_name="zeng_traffic_analytics",
        options="-c statement_timeout=120000",
    ) as connection:
        connection.read_only = True
        connection.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
        with connection.cursor() as cursor:
            cursor.execute(LABEL_SUMMARY_SQL)
            labels = prepare_label_summary(cursor.fetchall())
            cursor.execute(IMPORT_SUMMARY_SQL)
            imports = pd.DataFrame(
                cursor.fetchall(), columns=["batch_id", "source_file", "row_count"]
            )
    return labels, imports


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

# DONE
def main():
    # Main page display config 
    st.set_page_config(page_title="Network Traffic Overview", page_icon="Z")
    st.caption("Z-ENG: Network Intrusion Detection and Security Analytics Dashboard")
    st.title("Network Traffic Overview")
    
    #TODO: currently we use the dataset's original labels, model predictions to be added later :)

    with st.sidebar:
        st.header("Connect to the Database")
        with st.form("database_connection"):
            # TODO: Decide if leaving already declared values or remove all (or only pswrd) for security?
            host = st.text_input("Host", value="localhost")
            port = st.number_input("Port", min_value=1, max_value=65535, value=5432)
            database = st.text_input("Database name", value="zeng_security")
            username = st.text_input("Username", value="postgres")
            password = st.text_input("Password", type="password", value="holahola") 
            submitted = st.form_submit_button("Connect")

    if submitted:
        st.session_state.pop("analytics_result", None)
        try:
            # Appears while loading the database first
            with st.spinner("Calculating summaries in the database..."):
                labels, imports = load_summaries(host, int(port), database, username, password)
            st.session_state["analytics_result"] = {
                "labels": labels, "imports": imports,
                "loaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": f"{database} on {host}:{int(port)}",
            }
        # If the data for connecting to the database was not correct throw an error:
        except psycopg.OperationalError:
            st.error("Error: Check data submmited for the database connection.")

    result = st.session_state.get("analytics_result")
    if result is None:
        st.write("Enter your database connection details in the sidebar, then click **Connect**.")
        return

    st.caption(f"Database source: {result['target']}")

    render_overview(result["labels"], result["imports"])


if __name__ == "__main__":
    main()
