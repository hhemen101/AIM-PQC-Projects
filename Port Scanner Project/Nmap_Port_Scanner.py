import nmap
import time 

scan = nmap.PortScanner()

# Starts recording the time the scan started.
s_time = time.time()

# Scans the target host with service/version detection.
target = scan.scan('scanme.org', arguments='-sV')


for h in scan.all_hosts():
    print("host:", h)

    
    for protocol in scan[h].all_protocols():
        ports = scan[h][protocol].keys()

        # Integrates banner detection for all the open ports.
        for port in ports:
            banner = scan[h][protocol][port]
            product = banner.get('product', '')
            version = banner.get('version', '')
            info = banner.get('extrainfo', '')

            # Checks of there is any banner information.
            if not(product or version or info):                                    
                print(f"Port {port} is open. No banner receieved".strip())

            else:
                print(f"Port {port} is open. Banner: {product}{version}{info}".strip())

# Computes the total time the scan took and displays it in seconds.
e_time = time.time()
elasped_time = (e_time - s_time)
print (f"Time: {elasped_time:.2f} seconds")
