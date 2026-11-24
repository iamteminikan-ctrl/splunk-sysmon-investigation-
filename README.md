# Splunk Sysmon Security Investigation

## Project overview

This project documents a security investigation performed in Splunk Enterprise using Sysmon XML events. The investigation focuses on a PowerShell process (Process ID 7080), its process-creation record, associated network connections, a specific external destination, and a DNS-query search.

The goal is to demonstrate a practical security-operations workflow: extracting relevant fields from endpoint telemetry, correlating process and network events, documenting evidence, and distinguishing observed facts from assumptions.

## Tools and data

- **SIEM:** Splunk Enterprise
- **Telemetry:** Sysmon events represented as XML
- **Splunk index:** `main`
- **Sourcetype used in the searches:** `sysmon_xml`
- **Key Sysmon event IDs reviewed:**
  - `1` — Process creation
  - `3` — Network connection
  - `22` — DNS query

## Investigation highlights

### 1. Process creation

The search results show a Sysmon Event ID 1 for:

- Process: `powershell.exe`
- Process ID: `7080`
- Parent process: `cmd.exe`

The displayed command line includes `-NoProfile`, `-NonInteractive`, `-NoLogo`, `-WindowStyle hidden`, and `-ExecutionPolicy Unrestricted`. It also shows an EC2Launch module import and a `Set-Wallpaper` command. These options can occur in legitimate automation as well as suspicious activity, so they require host and administrative context before interpretation.

Evidence: [`01-process-creation.png`](evidence/01-process-creation.png)

### 2. Network connections

Three Sysmon Event ID 3 records were identified for Process ID `7080`:

| Source IP | Source port | Destination IP | Destination port | Protocol | Initiated |
|---|---:|---|---:|---|---|
| `10.0.1.14` | `59984` | `169.254.169.254` | `80` | TCP | `true` |
| `10.0.1.14` | `59985` | `169.254.169.254` | `80` | TCP | `true` |
| `10.0.1.14` | `59983` | `93.184.220.29` | `80` | TCP | `true` |

Evidence:
- [`02-network-connections.png`](evidence/02-network-connections.png)
- [`03-network-details.png`](evidence/03-network-details.png)

### 3. External destination review

A focused search for `93.184.220.29` returned one matching network event associated with `powershell.exe` (PID `7080`), originating from `10.0.1.14` and using TCP port `80`.

An IP address alone is not enough to determine whether the activity is benign or malicious. Additional endpoint, firewall, proxy, and threat-intelligence context would be needed.

Evidence: [`04-external-destination.png`](evidence/04-external-destination.png)

### 4. DNS-query review

A search for Sysmon Event ID `22` associated with Process ID `7080` returned zero matching events. This means no matching DNS-query record was found in the searched telemetry; it does not prove that DNS was never used.

Evidence: [`05-dns-investigation.png`](evidence/05-dns-investigation.png)

## Assessment

The available evidence supports these observations:

1. PowerShell process `7080` was created with `cmd.exe` shown as its parent.
2. The recorded command line includes hidden and non-interactive execution options.
3. Three network-connection events were recorded for the process.
4. One recorded connection targeted `93.184.220.29` over TCP port `80`.
5. The specific DNS Event ID 22 search returned no matching events.

These are investigative leads, not proof of malware execution, command-and-control activity, data exfiltration, or system compromise. The defensible conclusion from the reviewed screenshots is **activity requiring further investigation**.

## Data-quality note

The Splunk result tables show `_time` as `2026-11-03 09:28:59`, while raw XML visible in the screenshots includes a `SystemTime` value dated `2020-11-10`. This discrepancy should be validated by checking timestamp extraction, timezone handling, and ingestion configuration before building a definitive event timeline.

## Recommended follow-up

- Confirm whether the host is an AWS EC2 instance and whether the EC2Launch activity is expected.
- Review the complete raw Sysmon events, including user, host, process GUID, hashes, and timestamps.
- Correlate the process with nearby endpoint and network events. Prefer `ProcessGuid` where available because process IDs can be reused.
- Check firewall, proxy, endpoint, and DNS resolver logs for corroborating activity.
- Validate the timestamp discrepancy before finalizing the timeline.

## Repository structure

```text
splunk-sysmon-investigation/
├── README.md
├── evidence/
│   ├── 01-process-creation.png
│   ├── 02-network-connections.png
│   ├── 03-network-details.png
│   ├── 04-external-destination.png
│   └── 05-dns-investigation.png
└── reports/
    ├── Splunk_Security_Investigation_Report.docx
    └── Splunk_Security_Investigation_Report.pdf
```

## Disclaimer

This is a defensive security-learning project based on the Splunk screenshots and search results collected during the exercise. The report records the evidence available and avoids classifying the activity as malicious without corroboration.
