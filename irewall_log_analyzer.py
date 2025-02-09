import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# Configure Matplotlib for better visuals
sns.set_theme(style="darkgrid")

# Load firewall logs (Ensure logs are in CSV format)
LOG_FILE = "firewall_logs.csv"

# Define column names based on a sample log structure
columns = ["timestamp", "src_ip", "dest_ip", "protocol", "action", "bytes", "status"]

# Load the log file into a Pandas DataFrame
df = pd.read_csv(LOG_FILE, names=columns, parse_dates=["timestamp"])

# Convert timestamp to datetime if not already
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Filter logs with failed connections (e.g., "DENIED")
failed_attempts = df[df["status"] == "DENIED"]

# Count occurrences of each source IP
ip_counts = failed_attempts["src_ip"].value_counts()

# Detect anomaly: IPs with unusually high failed connection attempts
threshold = ip_counts.mean() + (2 * ip_counts.std())  # Simple statistical threshold
anomalous_ips = ip_counts[ip_counts > threshold]

# Print Anomalous IPs
print("🚨 Detected Anomalous IPs 🚨")
print(anomalous_ips)

# Trend Analysis: Failed attempts over time
failed_attempts["hour"] = failed_attempts["timestamp"].dt.hour
hourly_trends = failed_attempts.groupby("hour").size()

# Visualization: Failed Attempts Trend
plt.figure(figsize=(10, 5))
plt.plot(hourly_trends.index, hourly_trends.values, marker='o', linestyle='-')
plt.xlabel("Hour of the Day")
plt.ylabel("Failed Connection Attempts")
plt.title("Firewall Denied Requests Over Time")
plt.xticks(range(0, 24))
plt.show()

# Save the anomalous IPs to a CSV file
anomalous_ips.to_csv("anomalous_ips.csv", header=True)

print("✅ Anomaly detection completed. Results saved to anomalous_ips.csv")
