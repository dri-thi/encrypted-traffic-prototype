pip install streamlit scapy pandas scikit-learn matplotlib seaborn
streamlit run app.py
# app.py
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from scapy.all import rdpcap, IP, TCP, UDP

st.set_page_config(page_title="Encrypted Traffic Threat Hunting", layout="wide")

st.title("🔒 Encrypted Traffic Threat Hunting Without Decryption")
st.write("Prototype: Detect suspicious flows in encrypted traffic metadata (no payload inspection).")

# -----------------------------
# Upload Section
# -----------------------------
uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])
if uploaded_file:
    st.success("PCAP uploaded successfully!")

    # -----------------------------
    # Parse flows from PCAP
    # -----------------------------
    packets = rdpcap(uploaded_file)
    flows = {}
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        ts = float(pkt.time)
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        key = (src, dst, sport, dport)
        length = len(pkt)
        flows.setdefault(key, []).append((ts, length, dport))

    rows = []
    for key, pkts in flows.items():
        times = [p[0] for p in pkts]
        lengths = [p[1] for p in pkts]
        dport = pkts[0][2]
        flow_duration = max(times) - min(times) if len(times) > 1 else 0
        num_pkts = len(pkts)
        total_bytes = sum(lengths)
        avg_pkt = np.mean(lengths)
        iats = np.diff(sorted(times)) if len(times) > 1 else [0]
        mean_iat = np.mean(iats)
        rows.append({
            "src": key[0], "dst": key[1], "sport": key[2], "dport": key[3],
            "flow_duration": flow_duration, "num_pkts": num_pkts,
            "total_bytes": total_bytes, "avg_pkt_size": avg_pkt,
            "mean_iat": mean_iat, "is_tls": 1 if dport == 443 else 0
        })

    df = pd.DataFrame(rows)
    st.write("### Extracted Flows", df.head())

    # -----------------------------
    # ML Model
    # -----------------------------
    if not df.empty:
        features = ["flow_duration", "num_pkts", "total_bytes", "avg_pkt_size", "mean_iat", "is_tls"]
        X = df[features].replace([np.inf, -np.inf], 0).fillna(0)

        iso = IsolationForest(n_estimators=200, contamination=0.1, random_state=42)
        iso.fit(X)
        df["anomaly"] = (iso.predict(X) == -1).astype(int)
        df["anomaly_score"] = iso.decision_function(X)

        st.write("### Results (Flagged Suspicious Flows)")
        st.dataframe(df[df["anomaly"] == 1])

        # -----------------------------
        # Charts
        # -----------------------------
        st.write("### Visualizations")
        counts = df["anomaly"].value_counts().rename({0: "Normal", 1: "Suspicious"})
        st.bar_chart(counts)

        st.scatter_chart(df, x="avg_pkt_size", y="mean_iat", color="anomaly")

        # Save results
        df.to_csv("results.csv", index=False)
        st.download_button("Download Results CSV", df.to_csv(index=False), "results.csv", "text/csv")

