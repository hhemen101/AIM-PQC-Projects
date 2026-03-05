# Comparing Port Scanners
This project is designed to develop two types of port scanners and compare the performance of both. 

## Project Overview
- Developed an Nmap-based port scanner and service scanner that actively probes ports and applies built-in service detection techniques. 
- Developed a custom TCP socket-based scanner that performs basic TCP connect scans.
- Both scanners scan "scanme.org" for open ports to test if the scanner operates as intended.



## Project Structure and Logic

### Nmap-Based Port Scanner
- **Path:** `Port Scanner Project\Nmap_Port_Scanner.py`
- Scans the target host with service/version detection and automatically checks all ports.
- Automatically integrates banner detection for all open ports. 
- Validates if there is any banner information.
- Outputs the open port number and banner information, inclduing the product, version, and any extra information if provided.
- Displays the time the scanner took to scan the target host.

### Custom TCP-Based Port Scanner
- **Path:** `Port Scanner Project\Socket_Port_Scanner.py`
- Manually scans all ports ranging from 1 to 65535.
- Sends an HTTP GET request for banner grabbing so it can retrive the service banner of ports that do not automiatically send a response upon connection.
- Displays only the header if the banner retrieved has HTTP header/body, otherwise it displays the whole banner.
- Implements threading to improve the scanner's effiency
- Displays the time the scanner took to scan the target host.

## How to Run
Be in the root directory

### Prerequisites
```bash
git clone https://github.com/hhemen101/AIM-PQC-Projects/tree/main
```
- Make sure Nmap itself is downloaded on the host machine. https://nmap.org/download.html 
```bash
pip install python-nmap
```


## Comments and Key Findings
- Host target can be modified to scan hostnames, IP addresses, and Network ranges.
- There were significant performance differences.
- When scanning nmap.org, four open ports were detected and the Nmap scanner only took 9 seconds while the custom TCP socket-based scanner took 29 seconds to complete the scan.
- The Nmap scanner is more advanced as it had built-in features the custom TCP socket-based scanner does not have.
- The socket-based scanner needs an explixt range of ports to scan for open ports, while the Nmap-based scanner does not.
