# Comparing Port Scanners
This project compares two different approaches to port scanning:

1. An Nmap-based port scanner
2. A custom TCP socket-based scanner

The project's objective is to evaluate differences in scanning performance, detection capability, and functionality between an industry-standard tool and a custom-built implementation.

## Project Overview
- Implemented the Nmap-based port scanner using the Python wrapper to perform automated port and service detection.
- Developed a custom TCP socket-based scanner using Python sockets. 
- Implemented threading to improve the socket-based scanner's efficiency.
- Implemented banner grabber techniques in the TCP connect scanner to identify running services.
- Both scanners scan "scanme.org" for open ports to test if the scanner operates as intended.
- Compared scan results and execution time between the two scanning approaches.


## Project Structure and Logic

### Nmap-Based Port Scanner
- **Path:** `Port Scanner Project/Nmap_Port_Scanner.py`
- Scans the target host with service/version detection and automatically checks all ports.
- Actively probes ports and applies built-in service detection techniques.
- Automatically integrates banner detection for all open ports. 
- Validates if there is any banner information.
- Outputs the open port number and banner information, including the product, version, and any extra information if provided.


### Custom TCP-Based Port Scanner
- **Path:** `Port Scanner Project/Socket_Port_Scanner.py`
- Performs basic TCP connect scans.
- Manually scans all ports ranging from 1 to 65535.
- Sends an HTTP GET request for banner grabbing so it can retrieve the service banner of ports that do not automatically send a response upon connection.
- Displays only the header if the banner retrieved has HTTP header/body, otherwise it displays the whole banner.


## How to Run
Be in the root directory

### Prerequisites
```bash
git clone https://github.com/hhemen101/AIM-PQC-Projects.git
```
- Make sure Nmap itself is downloaded on the host machine. https://nmap.org/download.html 
```bash
pip install python-nmap
```
#### Nmap scanner

```bash
python Port Scanner Project/Nmap_Port_Scanner.py
```

#### TCP port scanner
```bash
python Port Scanner Project/Socket_Port_Scanner.py
```

## Comments and Key Findings
- Host target can be modified to scan hostnames, IP addresses, and network ranges.
- There were significant performance differences.
- When scanning nmap.org, four open ports were detected and the Nmap scanner only took 9 seconds while the custom TCP socket-based scanner took 29 seconds to complete the scan.
- The Nmap scanner provides more advanced capabilities, including built-in features and optimized scanning techniques that are not implemented in the custom TCP socket-based scanner.
- The socket-based scanner requires an explicit port range to be specified, while the Nmap-based scanner does not.

## Future Work
- Implement SYN-based port scanning.
- Add UDP scanning capability.
- Integrate CVE lookup using the National Vulnerability Database (NVD).

## Disclaimer

- This project is intended for educational and research purposes only. 
- Port scanning should only be performed on systems that you own or have explicit permission to test.