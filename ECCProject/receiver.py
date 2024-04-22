import socket

# Define the IP address and port to listen on
host = '0.0.0.0'  # Listen on all available network interfaces
port = 5000  # Same port number as defined in the Flask server

# Create a socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Bind the socket to the host and port
    s.bind((host, port))
    
    # Listen for incoming connections
    s.listen()
    print(f"Listening on {host}:{port}...")
    
    # Accept incoming connections
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        
        # Receive data from the connection
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print('Received:', data.decode())