import socket

def receive_message():
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Choose an IP address and port number to listen on
    ip_address = "0.0.0.0"  # Use "0.0.0.0" to listen on all available network interfaces
    port = 80  # Choose a port number

    # Initialize the 'conn' variable
    conn = None

    try:
        # Bind the socket to the IP address and port number
        s.bind((ip_address, port))

        # Listen for incoming connections
        s.listen(1)

        print("Waiting for connection...")

        # Accept the incoming connection
        conn, addr = s.accept()

        print(f"Connection established with {addr[0]}:{addr[1]}")

        # Receive the message from the sender
        data = conn.recv(4096).decode()
        encrypted_message = data.strip()  # Remove any leading/trailing white spaces

        print(f"Received encrypted message: {encrypted_message}")

    except OSError as e:
        print("Error occurred while setting up the receiver:", e)

    finally:
        # Close the connection and socket
        if conn:
            conn.close()
        s.close()


# Call the receive_message function to start receiving messages
receive_message()