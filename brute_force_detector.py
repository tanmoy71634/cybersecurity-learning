from collections import defaultdict


def analyze_log(log_data):
    
    tracker = defaultdict(lambda: {"failed_count": 0, "has_success": False})
    lines = log_data.strip().split("\n")

    for line in lines:
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) != 2:
            continue  

        ip, status = parts[0], parts[1].upper()
 # (Standard brute-force detection logic)
        if status == "FAILED":
            tracker[ip]["failed_count"] += 1
        elif status == "SUCCESS":
            if tracker[ip]["failed_count"] > 0:
                tracker[ip]["has_success"] = True

    # Process and print alerts
    for ip, stats in tracker.items():
        # Define threshold for brute-force alerting 
        if stats["failed_count"] >= 5:
            print("ALERT: Possible brute-force attack\n")
            print(f"IP: {ip}")
            print(f"Failed Attempts: {stats['failed_count']}")

            if stats["has_success"]:
                print("Successful Login After Failures: YES")
                print("Risk: HIGH")
            else:
                print("Successful Login After Failures: NO")
                print("Risk: MEDIUM")
            print("-" * 35)


# --- Example Usage ---
if __name__ == "__main__":
    log_file_content = """
    10.0.0.5 FAILED
    10.0.0.5 FAILED
    10.0.0.5 FAILED
    10.0.0.5 FAILED
    10.0.0.5 FAILED
    10.0.0.5 FAILED
    10.0.0.5 FAILED
    10.0.0.5 SUCCESS
    """

    analyze_log(log_file_content)

