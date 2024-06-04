import os

def ip_to_bytes(ip):
    """ Convert dots-and-numbers IPv4 address to a bytestring. """
    return bytes(int(part) for part in ip.split('.'))

def read_tcp_data(filename):
    """ Read binary TCP data from a file. """
    with open(filename, "rb") as file:
        return file.read()

def compute_checksum(data):
    """ Compute the TCP checksum using one's complement arithmetic. """
    if len(data) % 2 == 1:
        data += b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xffff) + (total >> 16)
    
    return (~total) & 0xffff

def validate_tcp_checksums():
    for i in range(10):
        # Read IP addresses
        with open(f"tcp_addrs_{i}.txt", "r") as file:
            source_ip, dest_ip = file.read().strip().split()
        
        # Convert IP addresses to bytes
        source_bytes = ip_to_bytes(source_ip)
        dest_bytes = ip_to_bytes(dest_ip)

        # Read TCP data
        tcp_data = read_tcp_data(f"tcp_data_{i}.dat")
        
        # Extract and zero out the checksum in the TCP data
        original_checksum = int.from_bytes(tcp_data[16:18], "big")
        tcp_zero_checksum = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

        # TCP length
        tcp_length = len(tcp_data)

        # Create pseudo header
        pseudo_header = source_bytes + dest_bytes + (0).to_bytes(1, byteorder='big') + (6).to_bytes(1, byteorder='big') + tcp_length.to_bytes(2, byteorder='big')

        # Concatenate pseudo header and TCP data with zeroed checksum
        full_data = pseudo_header + tcp_zero_checksum
        
        # Compute checksum
        computed_checksum = compute_checksum(full_data)
        
        # Compare checksums and determine result
        if computed_checksum == original_checksum:
            print("PASS")
        else:
            print("FAIL")

validate_tcp_checksums()
