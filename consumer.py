import socket

# UDP packet payload
data = b"Hello, UDP!"

# IP address and ports of the source and destination hosts
source_ip = "0.0.0.0"  # Use the appropriate source IP address
source_port = 335
destination_ip = "10.0.0.3"
destination_port = 1234  # Replace with the desired destination port

# DSCP value (36 in this case)
dscp_value = 36

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Set the DSCP field
sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, dscp_value << 2)

try:
    # Bind the socket to the source IP and port
    sock.bind((source_ip, source_port))

    # Send the UDP packet to the destination host
    sock.sendto(data, (destination_ip, destination_port))
    print("UDP packet sent successfully!")
finally:
    # Close the socket
    sock.close()

