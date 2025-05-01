import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.dates as mdates
import matplotlib.patches as mpatches


# Load logs
attacks = pd.read_csv("./Evil/evil_twin_log.csv", parse_dates=["start_time", "end_time"])
detections = pd.read_csv("./detector_v3/detection_log.csv", parse_dates=["timestamp"])

# Normalize
attacks["mode"] = attacks["mode"].astype(str)
detections["bssid"] = detections["bssid"].str.upper()

mode_desc = {
    "1": "Exact Clone (WPA2-PSK/CCMP)",
    "2": "BSSID Mismatch",
    "3": "Channel Mismatch",
    "4": "Auth Mismatch (TKIP)",
    "5": "WEP Evil Twin",
    "6": "OPEN Evil Twin"
}

# --- Summary Table ---
summary = []
for _, attack in attacks.iterrows():
    start, end = attack["start_time"], attack["end_time"]
    mode = attack["mode"]
    match = detections[(detections["timestamp"] >= start) & (detections["timestamp"] <= end)]
    count = len(match)
    reasons = match["reason"].value_counts().to_dict()
    summary.append({
        "mode": mode,
        "description": mode_desc.get(mode, f"Mode {mode}"),
        "start": start,
        "end": end,
        "detections": count,
        "reasons": reasons
    })

summary_df = pd.DataFrame(summary)
summary_df.to_csv("detection_summary.csv", index=False)

# --- Detection Count Bar ---
plt.figure(figsize=(10, 5))
plt.bar(summary_df["description"], summary_df["detections"], color="skyblue")
plt.xticks(rotation=30, ha='right')
plt.ylabel("Detections")
plt.title("Detections per Evil Twin Scenario")
plt.tight_layout()
plt.savefig("detections_per_scenario.png")
plt.show()

# --- Detection Rate Pie ---
detected = (summary_df["detections"] > 0).sum()
undetected = len(summary_df) - detected
plt.figure(figsize=(6, 6))
plt.pie(
    [detected, undetected],
    labels=["Detected", "Not Detected"],
    autopct="%1.1f%%",
    colors=["green", "red"]
)
plt.title("Detection Rate Across All Scenarios")
plt.savefig("detection_rate_pie.png")
plt.show()

# --- First Detection Latency ---
latencies = []
for _, row in attacks.iterrows():
    start, end = row["start_time"], row["end_time"]
    mode = row["mode"]
    bssid = row["bssid"].upper()
    match = detections[
        (detections["timestamp"] >= start) &
        (detections["timestamp"] <= end) &
        (detections["bssid"] == bssid)
    ]
    if not match.empty:
        latency = (match["timestamp"].min() - start).total_seconds()
    else:
        latency = None
    latencies.append({
        "mode": mode,
        "description": mode_desc.get(mode, f"Mode {mode}"),
        "latency_seconds": latency
    })

latency_df = pd.DataFrame(latencies)
latency_df.to_csv("first_detection_latency.csv", index=False)

# Bar: First Detection Latency
detected_df = latency_df.dropna()
plt.figure(figsize=(10, 5))
plt.bar(detected_df["description"], detected_df["latency_seconds"], color="steelblue")
plt.xticks(rotation=30, ha="right")
plt.ylabel("First Detection Latency (seconds)")
plt.title("First Detection Latency per Evil Twin Scenario")
plt.tight_layout()
plt.savefig("first_detection_latency_bar.png")
plt.show()


# --- Updated Timeline with Fixed Y-Positioning ---
fig, ax = plt.subplots(figsize=(14, 6))
y_labels = []
y_pos = []
detection_xs = []
detection_ys = []

attacks_sorted = attacks.sort_values("start_time").reset_index(drop=True)
plot_start = min(attacks_sorted["start_time"].min(), detections["timestamp"].min())
plot_end = max(attacks_sorted["end_time"].max(), detections["timestamp"].max())

# Track next Y position
y_val = 0

# --- Idle (Pre-Attack) ---
first_start = attacks_sorted["start_time"].min()
if (first_start - plot_start).total_seconds() >= 60:
    ax.barh(
        y=y_val,
        width=first_start - plot_start,
        left=plot_start,
        height=0.3,
        color="white",
        edgecolor="black",
        hatch="...."
    )
    y_labels.append("Idle (Pre-Attack)")
    y_pos.append(y_val)
    y_val += 2  # leave space

# --- Main Timeline Loop ---
for idx, row in attacks_sorted.iterrows():
    attack_y = y_val
    label = mode_desc.get(row["mode"], f"Mode {row['mode']}")
    
    # Plot attack
    ax.barh(
        y=attack_y,
        width=row["end_time"] - row["start_time"],
        left=row["start_time"],
        height=0.4,
        color="lightgrey"
    )
    y_labels.append(label)
    y_pos.append(attack_y)

    # Detection Xs
    match = detections[
        (detections["timestamp"] >= row["start_time"]) &
        (detections["timestamp"] <= row["end_time"])
    ]
    for ts in match["timestamp"]:
        detection_xs.append(ts)
        detection_ys.append(attack_y)

    # Grace Period
    if idx < len(attacks_sorted) - 1:
        gap_start = row["end_time"]
        gap_end = attacks_sorted.loc[idx + 1, "start_time"]
        if (gap_end - gap_start).total_seconds() >= 60:
            grace_y = y_val + 1
            ax.barh(
                y=grace_y,
                width=gap_end - gap_start,
                left=gap_start,
                height=0.3,
                color="white",
                edgecolor="black",
                hatch="////"
            )
            y_labels.append(f"Grace (Gap {idx + 1})")
            y_pos.append(grace_y)
            y_val += 2
        else:
            y_val += 2
    else:
        y_val += 2

# --- Idle (Post-Attack) ---
last_end = attacks_sorted["end_time"].max()
if (plot_end - last_end).total_seconds() >= 60:
    ax.barh(
        y=y_val,
        width=plot_end - last_end,
        left=last_end,
        height=0.3,
        color="white",
        edgecolor="black",
        hatch="...."
    )
    y_labels.append("Idle (Post-Attack)")
    y_pos.append(y_val)

# Plot detections
ax.plot(detection_xs, detection_ys, 'x', color='red')

# Format
ax.set_yticks(y_pos)
ax.set_yticklabels(y_labels)
ax.set_xlabel("Time")
ax.set_title("Attack vs Detection Timeline (with Grace & Idle Periods)")
ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=1))
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

# Legend
import matplotlib.patches as mpatches
handles = [
    mpatches.Patch(color="lightgrey", label="Attack"),
    mpatches.Patch(facecolor="white", edgecolor="black", hatch="////", label="Grace Period"),
    mpatches.Patch(facecolor="white", edgecolor="black", hatch="....", label="Idle Period"),
    plt.Line2D([], [], color='red', marker='x', linestyle='None', label="Detection")
]
ax.legend(handles=handles, loc="upper left", fontsize="small")

plt.tight_layout()
plt.savefig("timeline_final.png")
plt.show()
