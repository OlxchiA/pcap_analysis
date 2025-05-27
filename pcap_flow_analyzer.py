import sys
import pyshark
from scapy.all import *
import re
from datetime import datetime
from pathlib import Path

# as input, a number that tracks the amount of time this script is called - should be four 
def get_user_input():
    """ Prompt the user to input details required for analyzing a pcap file.

    Returns a tuple containing the following user inputs:
            - filepath (str): The path to the pcap file.
            - ue_ip (str): The User Equipment (UE) IP address.
            - server_ip (str): The server IP address.
    """
    # to add: correction checks for inputs 
    filepath = input("Enter the path to the pcap file: ")
    ue_ip = input("Enter the UE IP address: ")
    server_ip = input("Enter the server IP address: ")
    return filepath, ue_ip, server_ip

def filter_pcap(filepath,ue_ip,server_ip):
    """
    Filters packets from a PCAP file based on IP addresses and categorizes them into specific streams.
    This function uses the PyShark library to analyze a PCAP file and filter packets based on the provided
    user equipment (UE) IP address and server IP address. It then categorizes the packets into four streams:
    "S1U-UL", "SGi-UL", "SGi-DL", and "S1U-DL", based on their direction and flags.
    Args:
        filepath (str): The path to the PCAP file to be analyzed.
        ue_ip (str): The IP address of the user equipment (UE).
        server_ip (str): The IP address of the server.
    Returns:
        dict: A dictionary containing categorized packets in the following keys:
            - "S1U-UL": List of packets in the S1U uplink direction.
            - "SGi-UL": List of packets in the SGi uplink direction.
            - "SGi-DL": List of packets in the SGi downlink direction.
            - "S1U-DL": List of packets in the S1U downlink direction.
    Notes:
        - The function uses a display filter to limit the packets to those involving the specified IP addresses.
        - Packets are categorized based on the direction bits extracted from the packet flags.
        - If a packet does not have the required attributes, it is skipped.
    """

    # filter pcap file to only include packets where the IP address is either server or ue IP specified 
    disp_filter = f"ip.addr == {ue_ip} or ip.addr == {server_ip}"
    cap = pyshark.FileCapture(filepath, display_filter=disp_filter)

    stream_dict = {
    "S1U-UL": [],
    "SGi-UL": [],
    "SGi-DL": [],
    "S1U-DL": []
    }

    # loop through each packet 
    for packet in cap:
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst 

            # if source IP is user and destination IP is server
            if (ue_ip == ip_src and server_ip == ip_dst):

                # check direction
                # check packet flags to get direction bits
                flags_hex = str(packet.frame.packet_flags_direction)  # e.g., '0x00000001'
                flags_int = int(flags_hex, 16)       # Convert hex string to int
                direction_bits = flags_int & 0x3     # Mask to get lowest 2 bits

                # if direction is 1, packet is in S1U-UL stream, if it's 2 then packet is SGi-UL stream
                if  (direction_bits == 1):
                    stream_dict["S1U-UL"].append(packet)
                elif (direction_bits == 2):
                    stream_dict["SGi-UL"].append(packet)

            # if source IP is server and destination IP is user
            elif (ue_ip == ip_dst and server_ip == ip_src):
                # check direction
                flags_hex = str(packet.frame.packet_flags_direction)  # e.g., '0x00000001'
                flags_int = int(flags_hex, 16)       # Convert hex string to int
                direction_bits = flags_int & 0x3     # Mask to get lowest 2 bits

                # if direction is 1, packet is in SGi-DL stream, if it's 2 then packet is S1U-DL stream
                if (direction_bits == 1):
                    stream_dict["SGi-DL"].append(packet)
                elif (direction_bits == 2):
                    stream_dict["S1U-DL"].append(packet)

        # if the packet does not have a 'frame' layer skip over it
        except AttributeError:
            print("This packet does not have a frame layer")
            continue

    cap.close()
    return stream_dict


def checksequence(packets_by_stream_dict):
    """
    Analyzes packets grouped by streams to verify sequence numbers and arrival times.
    This function iterates through a dictionary of packet streams, where each key represents
    a stream and the corresponding value is a list of packets. For each packet, it checks 
    if the data length is exactly 57 bytes, extracts the sequence number and arrival time, 
    and stores them as tuples in a list. It then verifies if the sequence numbers are in 
    the correct order for each stream.
    Args:
        packets_by_stream_dict (dict): A dictionary where keys are stream identifiers and 
                                       values are lists of packet objects.
    Returns:
        int: Always returns 0 upon successful execution.
    Raises:
        SystemExit: If a packet's data length is not 57 bytes, the function exits with an error message.
    Notes:
        - If a packet does not have the required attributes (e.g., no data field), it is skipped, 
          and a warning is printed.
        - The function relies on an external helper function `check_seq_order` to validate the 
          sequence order of packets within each stream.
    """

    # for each stream (key)
    for key, values in packets_by_stream_dict.items():
        seq_nums = [] # list holds tuples ((seq_num1,arrival_time1),(seq_num2,arrival_time2),...)
        # for each packet in the stream
        for packet in values:
            try:
                # check if each packet has data length 57
                if not (int(packet.data.data_len) == 57):
                    print(int(packet.data.data_len))
                    exit(f"Error: packet length is {int(packet.data.data_len)} should be 57")
                else:
           # extract sequence number from packet and time of arrival UTC - put in tuple and append to list
                    hex_str = str(packet.data.data)
                    arrival_time = str(packet.frame.time_utc)[:-7]
                    utc_time = datetime.strptime(arrival_time, "%b %d, %Y %H:%M:%S.%f")
                    seq_num = int(hex_str[10:12], 16)
                    seq_nums.append((seq_num, utc_time))


            except AttributeError:
                print(f"Warning: Packet {packet.frame.number} does not have the required attributes (maybe no data field) and thus was skipped.")
                continue

        # for list of tuples created for this stream, check if the sequence numbers are in order
        check_seq_order(seq_nums, key)


    return 0;

def check_seq_order(seq_nums, stream):
    """
    Check if the sequence numbers in a given stream are in order and print the result.
    This function takes a list of tuples containing sequence numbers and their 
    corresponding arrival times, and verifies if the sequence numbers are in 
    non-decreasing order. If they are not, it identifies and prints details 
    about the packets that are out of sequence.
    Args:
        seq_nums (list of tuples): A list of tuples where each tuple contains 
                                   a sequence number (int) and an arrival time (datetime).
        stream (str): A string representing the name or identifier of the stream.
    Returns:
        boolean: wheather or not the packets are in order
    Prints:
        - A message indicating that all sequence numbers are in order if no violations are found.
        - For each out-of-sequence packet, a message with the sequence number, 
          the stream name, and the arrival time of the packet.
    """

    # sort by arrival time
    seq_nums = sorted(seq_nums, key=lambda x: x[1])
    sequences = [seq for seq,_ in seq_nums]
    in_order = True

    # check if sequence numbers are in order by checking if the current sequence number is equal to the previous one + 1
    # some packets have missing data so allowances are made for when the sequence number is 0 or 2
    for (prev_seq, prev_time), (curr_seq, curr_time) in zip(seq_nums, seq_nums[1:]):
        if not(curr_seq == prev_seq + 1):
            if (curr_seq == 0):
                continue
            if (prev_seq == 0 and curr_seq == 2):
            #    print(f"missing data field in previous packet")
                continue
            in_order = False
            print(
                f"Packet with seq num {curr_seq} arrived out of sequence "
                f"in the {stream} stream at time {curr_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
            )
    if in_order:
        print(f"all in order in the stream: {stream}") 
        print(sequences)
    #    print("seq_nums:\n" + "\n".join(f"{seq}, {ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}" for seq,ts in seq_nums))
    
    return in_order    

if __name__ == "__main__":
    # These are the UE, SERVER IPs I used to test on
    UE_SERVER_IPS = ["44.236.4.33","25.62.224.209"]
    # 25.62.217.23
    # 44.232.52.182   25.62.224.209
    # 52.89.177.221   25.62.224.209
    # UETRACE_20250415_172731_UP-payload_eric-pc-up-data-plane-76cdc7548c-8slfs_9383jenkins_3.pcapng
    # 44.232.52.182   25.62.224.209
    # UETRACE_20250415_173914_UP-payload_eric-pc-up-data-plane-76cdc7548c-8slfs_9383jenkins_4.pcapng
    # 52.89.177.221   25.62.224.209
    # UETRACE_20250415_181211_UP-payload_eric-pc-up-data-plane-76cdc7548c-7tljr_9383jenkins_4.pcapng
    # 25.62.224.209 44.236.4.33
    # UETRACE_20250415_181211_UP-payload_eric-pc-up-data-plane-76cdc7548c-8slfs_9383jenkins_5.pcapng
    # 25.62.224.209 44.236.4.33
    # UETRACE_20250415_182757_UP-payload_eric-pc-up-data-plane-76cdc7548c-7tljr_9383jenkins_5.pcapng
    # 25.62.224.209 44.232.104.76
    # UETRACE_20250415_182757_UP-payload_eric-pc-up-data-plane-76cdc7548c-8slfs_9383jenkins_6.pcapng
    # 25.62.224.209 44.232.104.76
    # UETRACE_20250415_184422_UP-payload_eric-pc-up-data-plane-76cdc7548c-7tljr_9383jenkins_6.pcapng
    # 25.62.224.209 44.236.4.33
    # UETRACE_20250415_184422_UP-payload_eric-pc-up-data-plane-76cdc7548c-8slfs_9383jenkins_7.pcapng
    # 25.62.224.209 44.236.4.33

    # Get user input for the pcap file path and other parameters
    filepath, ue_ip, server_ip = get_user_input()

    # filter pcap file, divide packets into their streams
    packets_by_stream = filter_pcap(filepath, ue_ip, server_ip)

    # check sequence numbers in each stream
    checksequence(packets_by_stream)
    
