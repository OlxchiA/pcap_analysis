import sys
import pyshark
from scapy.all import *
import re
from datetime import datetime

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

def determine_stream(pdi_nw_name_value, direction):
    """Determine the stream based on PDI network name value and direction."""
    if pdi_nw_name_value == "internet":
        if direction == "inbound":
            stream = "S1U-UL" # access inbound stream
            print("stream: S1U-UL")
        elif direction == "outbound":
            stream = "SGi-UL" # access outbound stream
            print("stream: SGi-UL")

    elif pdi_nw_name_value == "media":
        if direction == "inbound":
            stream = "SGi-DL" # media inbound stream
            print("stream: SGi-DL")
        elif direction == "outbound":
            stream = "S1U-DL"
            print("stream: S1U-DL")
    else:
        print("Unable to determine stream from inputs")
        return -1
    
    return stream


def filter_pcap(filepath, ue_ip, server_ip, pdi_nw_name_value, fwd_nw_name_value, direction):
    """
    Filters packets from a pcap file based on specified IP addresses, network names, and packet direction.
    Args:
        filepath (str): Path to the pcap file to be analyzed.
        ue_ip (str): IP address of the User Equipment (UE).
        server_ip (str): IP address of the server.
        pdi_nw_name_value (str): Expected value of the 'pdi_nw_name' field in the packet comments.
        fwd_nw_name_value (str): Expected value of the 'fwd_nw_name' field in the packet comments.
        direction (str): Direction of the packet flow to filter ('inbound' or 'outbound').
    Returns:
        list: A list of filtered packets that match the given criteria.
        Note: If you want to print the list to command, uncomment the print statement in the function.
    """
    # Read the pcap file using PyShark, only load packets with the specified IP addresses
    disp_filter = f"ip.addr == {ue_ip} or ip.addr == {server_ip}"
    cap = pyshark.FileCapture(filepath, display_filter=disp_filter)

    # Filter packets based on the given parameters
    filtered_packets = []
    count = 0

  #  For each packet in the capture file, check if matches given criteria
    for packet in cap:
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst


            # if the source/destination IPs are the UE or server IP
            if  ((ue_ip == ip_src or ue_ip == ip_dst) and (server_ip == ip_src or server_ip == ip_dst)):

                # check packet comment layer
                comment = str(packet.frame_info.frame_comment_expert)
                comment_text = comment.replace(r'\n', '\n')

                # use regex to extract pdi_nw_name and fwd_nw_name from the comment text
                pdi_nw_name = re.search(r'pdi_nw_name:\s*(\w+)', comment_text).group(1)
                fwd_nw_name = re.search(r'fwd_nw_name:\s*(\w+)', comment_text).group(1)

                # if the names match given criteria
                if ((fwd_nw_name_value == fwd_nw_name) and (pdi_nw_name_value == pdi_nw_name)):

                    # check packet flags to get direction bits
                    flags_hex = str(packet.frame.packet_flags_direction)  # e.g., '0x00000001'
                    flags_int = int(flags_hex, 16)       # Convert hex string to int
                    direction_bits = flags_int & 0x3     # Mask to get lowest 2 bits

                    # if direction matches given criteria
                    if ((direction_bits == 1) and (direction == 'inbound')) or ((direction_bits == 2) and (direction == 'outbound')):                    
                                # then packet matches all criteria, add it to our list
                                filtered_packets.append(packet)

        except AttributeError:
            continue

    cap.close()
 #   print(str(filtered_packets))
    return filtered_packets

    # write to a pcap file (use scapy and select frame numbers that are equal to filtered frame numbers)
    
def checksequence(filtered_packets):
    """
    Processes a list of filtered packets to validate their data length, extract sequence numbers, 
    and record their arrival times in UTC.
    Args:
        filtered_packets (list): A list of packet objects to be analyzed. Each packet is expected 
                                 to have attributes `data.data_len`, `data.data`, and `frame.time_utc`.
    Returns:
        list: A list of tuples where each tuple contains:
              - seq_num (int): The extracted sequence number from the packet.
              - arrival_time (datetime): The UTC arrival time of the packet.
    Raises:
        SystemExit: If any packet's data length is not equal to 57, the function exits with an error message.
    Note:
        - The function assumes that the `filtered_packets` list contains packets with the required attributes.
        - The `data.data` attribute is expected to be a hexadecimal string from which the sequence number 
          is extracted.
        - The `frame.time_utc` attribute is expected to be a string representing the UTC time of arrival.
        - Uncomment the print statement to see a list of all the sequence numbers and arrival times.
    """
    
    seq_nums = [] # list holds tuples ((seq_num1,arrival_time1),(seq_num2,arrival_time2),...)
    count = 0
    for packet in filtered_packets:
        # check if each packet has data length 57
        if not (int(packet.data.data_len) == 57):
            print(int(packet.data.data_len))
            exit(f"Error: packet length is {int(packet.data.data_len)} should be 57")
            
        # extract sequence number from packet and time of arrival UTC - put in tuple and append to list
        else:
            hex_str = str(packet.data.data)
            arrival_time = str(packet.frame.time_utc)[:-7]
            utc_time = datetime.strptime(arrival_time, "%b %d, %Y %H:%M:%S.%f")
            seq_num = int(hex_str[10:12], 16)
            seq_nums.append((seq_num, utc_time))
        #    print(f"seq_num: {seq_num} arrival_time: {utc_time}")     

   # print(seq_nums)
    return seq_nums # return list of tuples (seq_num, arrival_time)

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
        int: Always returns 0. The return value is not used for any specific purpose.
    Prints:
        - A message indicating that all sequence numbers are in order if no violations are found.
        - For each out-of-sequence packet, a message with the sequence number, 
          the stream name, and the arrival time of the packet.
    """
    ''' Check if the sequence numbers are in order and print the result.\
        Input: list of tuples (seq_num, arrival_time)'''
    sequences = [seq for seq,_ in seq_nums]
    
    # check if sequence numbers are in order 
    if all (x <= y for x,y in zip(sequences, sequences[1:])):
        print(f"all in order in the stream: {stream}")
    else:
        # Print one message per violation
        for (prev_seq, prev_time), (curr_seq, curr_time) in zip(seq_nums, seq_nums[1:]):
            if curr_seq < prev_seq:
                print(
                    f"Packet with seq num {curr_seq} arrived out of sequence "
                    f"in the {stream} stream at time {curr_time}"
                )
    return 0


def filter_per_stream(filepath, ue_ip, server_ip, pdi_nw_name_value, fwd_nw_name_value, direction):
    ''' This is the main function that filters packets per stream and checks the sequence order.
        Input: filepath, ue_ip, server_ip, pdi_nw_name_value, fwd_nw_name_value, direction
        Output: prints the stream name and whether the packets are in order or not.'''

    # determine stream 
    stream = determine_stream(pdi_nw_name_value, direction)
    if (stream == -1):
        print("Error: Unable to determine stream from inputs")
        sys.exit(1)

    # filter packet and check the sequence order
    pckts = filter_pcap(filepath, ue_ip, server_ip, pdi_nw_name_value, fwd_nw_name_value, direction)

    # check sequence order
    seq_nums = checksequence(pckts)
    check_seq_order(seq_nums, stream)
    

if __name__ == "__main__":
    # These are the UE, SERVER IPs I used to test on
    UE_SERVER_IPS = ["44.236.4.33","25.62.224.209"]

    # Get user input for the pcap file path and other parameters
    filepath, ue_ip, server_ip = get_user_input()

    # Run our main function 4 times, one for each stream so packets are divided into 4 streams 
    for i in range(4):
        match i:
            case 0:
                pdi_nw_name_value = "internet"
                fwd_nw_name_value = "media"
                direction = "inbound"
            case 1:
                pdi_nw_name_value = "internet"
                fwd_nw_name_value = "media"
                direction = "outbound"
            case 2:
                pdi_nw_name_value = "media"
                fwd_nw_name_value = "internet"
                direction = "inbound"
            case 3:
                pdi_nw_name_value = "media"
                fwd_nw_name_value = "internet"
                direction = "outbound"
        
        filter_per_stream(filepath, ue_ip, server_ip, pdi_nw_name_value, fwd_nw_name_value, direction)
    
