from collections import defaultdict

successful_logins = 0
failed_logins = 0
alerts = []
event_counts = defaultdict(int)

try:
    with open("events.log", "r") as file:

        for line in file:

            # Skip empty lines
            if not line.strip():
                continue

            parts = line.strip().split()

            # Skip malformed lines
            if len(parts) < 2:
                continue

            event_id = parts[0]
            event_type = parts[1]

            # Count all events
            event_counts[event_id] += 1

            # Successful login
            if event_id == "4624":
                successful_logins += 1

            # Failed login
            elif event_id == "4625":
                failed_logins += 1

            # Security log cleared
            elif event_id == "1102":
                alerts.append(
                    "[HIGH] Security Log Cleared (Event ID 1102)"
                )

            # New user created
            elif event_id == "4720":
                alerts.append(
                    "[MEDIUM] New User Account Created (Event ID 4720)"
                )

            # User added to privileged group
            elif event_id == "4732":
                alerts.append(
                    "[HIGH] User Added To Privileged Group (Event ID 4732)"
                )

except FileNotFoundError:
    print("Error: events.log file not found.")
    exit()

# Detect brute-force style behavior
if failed_logins >= 5:
    alerts.append(
        f"[HIGH] Possible Brute-Force Attack Detected ({failed_logins} failed logins)"
    )

# Print Report
print("\n" + "=" * 50)
print(" WINDOWS SECURITY LOG ANALYSIS REPORT ")
print("=" * 50)

print(f"\nSuccessful Logins : {successful_logins}")
print(f"Failed Logins     : {failed_logins}")

print("\nEvent Statistics")
print("-" * 50)

for event_id, count in sorted(event_counts.items()):
    print(f"Event ID {event_id}: {count}")

print("\nSecurity Alerts")
print("-" * 50)

if alerts:
    for alert in alerts:
        print(alert)
else:
    print("No critical security alerts detected.")

print("\nAnalysis Complete.")
print("=" * 50)

