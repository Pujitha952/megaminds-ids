"""Streamlit analyst dashboard:  streamlit run dashboard.py

Pick a bundled pcap (or upload your own classic .pcap), choose rules / ml / hybrid, and inspect the
flagged events with the reason behind each one.
"""
import glob
import os
import tempfile

import pandas as pd
import streamlit as st

from idslib.detector import MODES, MODEL_PATH, detect
from idslib.report import SEV_COLOR, timeline_png

PCAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "pcaps")

st.set_page_config(page_title="AI-driven IDS", layout="wide")
st.title("Network traffic analysis & intrusion detection")

with st.sidebar:
    st.header("Input")
    bundled = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))
    choice = st.selectbox("Bundled capture", bundled, format_func=os.path.basename,
                          index=bundled.index(os.path.join(PCAP_DIR, "s2_portscan.pcap"))
                          if os.path.join(PCAP_DIR, "s2_portscan.pcap") in bundled else 0)
    up = st.file_uploader("...or upload a .pcap (classic format, Ethernet)", type=["pcap"])
    mode = st.radio("Detection mode", MODES, index=2,
                    help="rules = signature/threshold layer, ml = Isolation Forest, hybrid = both")
    window = st.slider("Window (s)", 1.0, 30.0, 5.0, 1.0)

path = choice
if up is not None:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    tmp.write(up.getbuffer())
    tmp.close()
    path = tmp.name

try:
    res = detect(path, mode, window, MODEL_PATH)
except Exception as e:                                  # surface parse / model errors to the user
    st.error(str(e))
    st.stop()

cap = res.cap
c1, c2, c3, c4 = st.columns(4)
c1.metric("Packets", f"{cap.n_packets:,}")
c2.metric("Duration", f"{cap.t1 - cap.t0:.0f} s")
c3.metric("Source-windows", len(cap.df))
c4.metric("Alerts", len(res.alerts))

st.image(timeline_png(res, title=os.path.basename(path)), use_container_width=True)

if not res.alerts:
    st.success("No alerts - traffic looks normal.")
    st.stop()

df = res.alerts_df()
sev = st.multiselect("Severity", list(SEV_COLOR), default=list(SEV_COLOR))
df = df[df["severity"].isin(sev)]
st.dataframe(df.drop(columns=["why"]), use_container_width=True, hide_index=True)

st.subheader("Why was it flagged?")
by_id = {a["id"]: a for a in res.alerts}
pick = st.selectbox("Alert", df["id"].tolist(),
                    format_func=lambda i: f"#{i}  {by_id[i]['src']}  {by_id[i]['category']}  t={by_id[i]['t_start']:.0f}s")
a = by_id[pick]
st.markdown(f"**{a['category']}** from `{a['src']}` -> `{a.get('dst') or '-'}`  \n"
            f"severity **{a['severity']}**, confidence **{a['confidence']:.2f}** (heuristic, not a calibrated probability), "
            f"detected by **{a['detector']}**")
st.info(a["why"])
st.json(a["evidence"])
row = cap.df[(cap.df.window == a["window"]) & (cap.df.src == a["src"])]
st.caption("Raw feature row for this window:")
st.dataframe(row.T.rename(columns=lambda c: "value"), use_container_width=True)
