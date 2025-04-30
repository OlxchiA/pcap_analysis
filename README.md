# PCAP Analysis
Python scripts that contain functions to help analyze and filter pcap files, checking if their sequence numbers are out of order and ordering them into their streams.
Running the main script, pcap_flow_analyzer.py divides a pcap file into streams based on the users input of IP addresses and outputs whether or not the packet sequence numbers are out of order. Functions have the ability to list packet files if you run them directly. Python 3.10 > is needed for the match statement. 

## Features
Filters packets based on:
- Source and destination IP addresses.
- pdi_nw_name and fwd_nw_name values in packet comments.
- Packet direction (inbound or outbound).
- Divides packets into four streams based on pdi_nw_name and direction.
- Checks the sequence order of packets in each stream.
- Provides detailed logs for out-of-sequence packets.

## How It Works
### Stream Determination:
The script determines the stream based on pdi_nw_name and direction:
- internet + inbound: S1U-UL
- internet + outbound: SGi-UL
- media + inbound: SGi-DL
- media + outbound: S1U-DL
  
### Packet Filtering:
Filters packets based on:
- Source and destination IPs.
- pdi_nw_name and fwd_nw_name in packet comments.
- Packet direction from flags.

### Sequence Check:
- Extracts sequence numbers and timestamps from packets.
- Validates if the sequence numbers are in order.
- Logs any out-of-sequence packets.

# GTP Packet Filter
This Python script pcap_gtp_filter.py filters GTP (GPRS Tunneling Protocol) packets from a given PCAP file and writes the filtered packets to a new PCAP file. It uses the Scapy library for packet manipulation.

## Features
- Reads packets from an input PCAP file.
- Filters packets containing the GTP_U_Header layer.
- Writes the filtered GTP packets to an output PCAP file.
- Displays statistics about the total packets and filtered GTP packets.

# Requirements
- Python 3.10 > is needed for the match statement in pcap_flow_analyzer.py (can be easily changed to an if-elif statement however)
- Make sure the PCAP files are in the same directory as the python files. For gtp_packet_filter.py change the input_file and output_file values with desired filepath.
- uses pyshark, scapy, re (regex library) to extract packet comments, and datetime
- All requirements/libraries are available in requirements.txt file. You can download all requirements to your environment with the following command:
```
pip install -r requirements.txt
```

To run: just open in any given IDE, optionally create a virtual environment, download dependencies, and press run!
