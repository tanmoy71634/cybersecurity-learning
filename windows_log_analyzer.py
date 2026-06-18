successful_logins = 0
failed_logins = 0
alerts = []

with open("events.log", "r") as file:
    for line in file:

        if not line.strip():
            continue
            
        parts = line.strip().split()
        
       
        if len(parts) < 2:
            continue

        event_id = parts[0]
        event_type = parts[1]

        print(event_id, event_type)


        if event_id == "4624":
            successful_logins += 1
        elif event_id == "4625":
            failed_logins += 1
        elif event_id == "1102":
            alerts.append("Security Log Cleared (Event ID 1102)")


print("\n--- SUMMARY ---")
print(f"Successful Logins: {successful_logins}")
print(f"Failed Logins: {failed_logins}")

print("\nALERTS:")
if alerts:
    for alert in alerts:
        print("-", alert)
else:
    print("- No critical security alerts triggered.")