import socket
import struct

# Create a normal socket to receive and send packets
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the local IP address and port
s.bind(("10.0.0.3", 635))  # Change this to your own IP address and desired port

# Set the payload data
data = b"the key to life"

# Loop forever
while True:
    # Receive a packet from any source
    packet, addr = s.recvfrom(65535)

    # Get the source IP address and port
    ip_src = addr[0]
    udp_src_port = addr[1]

    # Unpack the IP header fields
    ip_header = packet[:20]

    # Check if the IP header has a buffer size of 20 bytes
    if len(ip_header) == 20:
        ip_version, ip_tos, ip_length, ip_id, ip_flags, ip_ttl, ip_protocol, ip_checksum, ip_src, ip_dst = struct.unpack(
            "!BBHHHBBH4s4s", ip_header
        )

        # Print the extracted IP source address
        print("Source IP address:", socket.inet_ntoa(ip_src))

        # Check if the TOS value is 20
        if ip_tos == 20:
            # Check if the source port is 335
            if udp_src_port == 335:
                # Set the destination port as 335
                udp_dst_port = 335

                # Set the TOS value as 20
                s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 20)

                # Send the packet to the original source IP address and port
                s.sendto(data, (socket.inet_ntoa(ip_src), udp_dst_port))
    else:
        print("Invalid IP header length:", len(ip_header))

