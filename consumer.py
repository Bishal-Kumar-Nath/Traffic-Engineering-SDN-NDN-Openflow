import socket
import struct

# Create a normal socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Set the source IP address
#src_ip = "127.0.0.1"  # Change this to your own IP address
src_ip = "10.0.0.1" # Change this to your own IP address

# Set the destination IP address
dst_ip = "10.0.0.3"
#dst_ip = "127.0.0.1"

# Set the source port
src_port = 335

# Set the destination port
dst_port = 635  # Change this to your desired port

# Set the payload data
data = b"Hello world"

# Bind the socket to the source IP address and port
s.bind((src_ip, src_port))

# Set the TOS value as 20
s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 20)

# Create the IP header
ip_version = 4  # IP version (IPv4)
ip_ihl = 5  # Internet Header Length (default value)
ip_tos = 20  # Type of Service (TOS)
ip_total_length = 20 + len(data)  # Total length of the IP packet
ip_id = 0  # Identification (set as 0 for simplicity)
ip_flags = 0  # Flags (set as 0 for simplicity)
ip_ttl = 255  # Time to Live (TTL)
ip_protocol = socket.IPPROTO_UDP  # Protocol (UDP)
ip_checksum = 0  # Checksum (set as 0 for simplicity)
ip_src = socket.inet_aton(src_ip)  # Source IP address
ip_dst = socket.inet_aton(dst_ip)  # Destination IP address

# Pack the IP header fields into a binary string
ip_header = struct.pack("!BBHHHBBH4s4s", (ip_version << 4) + ip_ihl, ip_tos, ip_total_length, ip_id, ip_flags, ip_ttl,
                        ip_protocol, ip_checksum, ip_src, ip_dst)

# Send the packet (IP header + payload) to the destination IP address and port
s.sendto(ip_header + data, (dst_ip, dst_port))

