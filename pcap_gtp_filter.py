from scapy.all import *
from scapy.contrib.gtp import *
import ipaddress
from collections import defaultdict
import binascii

AWS_SERVER_IPS = {"44.236.4.33","52.89.177.221"}

def filter_gtp_packets(input_file, output_file):
    # Read the pcap file
    packets = rdpcap(input_file)

    # filter gtp packets
    gtp_packets = [pkt for pkt in packets if GTP_U_Header in pkt]

    # write the filtered packets to the output file
    wrpcap(output_file, gtp_packets)

    print(f"total packets {len(packets)}")
    print(f"gtp packets {len(gtp_packets)}")
    print(f"filtered packets written to {output_file}") 

if __name__ == "__main__":
    input_file = "213195_3.pcap"
    output_file = "213195_3_gtp.pcap"
    filter_gtp_packets(input_file, output_file)
