import socket
import time
import threading

# Ensures that each statement is printed one at a time.
print_lock = threading.Lock()

# This is the target host that will be scanned.
target = "scanme.org"

# Starts recording the time the scan started.
s_time = time.time()

threads = []

def scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # This is the set timeout for each connection attempt.
        s.settimeout(0.2)
        try:
            t_port = (target, port)

            # Attempts to connect to a port.
            s.connect(t_port)
            try:

                # Sends an HTTP GET request for banner grabbing.
                s.sendall(b'GET / HTTP/1.0\r\nHost: scanme.org\r\n\r\n')

                # Trys to recieve a banner.
                banner = s.recv(1024).decode(errors='ignore').strip()

                
                with print_lock:  
                    if banner:      
                        # If the banner has HTTP header/body, it only displays the header.
                        if '\r\n\r\n' in banner:
                                
                            header = banner.split('\r\n\r\n')[0]

                                
                            print (f"port {port} | Banner: {header}")

                            # Otherwise, it displays the whole banner that was received.
                        else:
                            
                            print (f"port {port} | Banner: {banner}")

                    else:
                       
                            print (f"port {port} | Banner: No banner received")
            except:
                
                print (f"port {port} | Banner: No banner received")
                
        except(socket.timeout):
            
            pass
        
    except Exception as e:
        
        with print_lock:
            print("Unexpected error")
            s.close()
       
    
# Scans all the ports ranging from 1 to 65535.
for p in range(1, 65535):
    thread = threading.Thread(target=scan, args=[p])
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()

# Stops recording the time when the scan is finished.
e_time = time.time()

# Computes the total time the scan took and displays it in seconds.
elasped_time = (e_time - s_time)
print (f"Elasped time: {elasped_time:.2f} seconds")

