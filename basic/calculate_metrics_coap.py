import pyshark
from datetime import datetime

def get_packets(file):
    capture = pyshark.FileCapture(file, display_filter='coap')
    packet_list = []

    for packet in capture:
        coap_layer = packet.coap
        timestamp = packet.sniff_time
        packet_size = int(packet.length)

        try:
            payload = coap_layer.payload.binary_value if hasattr(coap_layer, 'payload') else None
            if not payload and 'data' in coap_layer.field_names:
                payload = bytes.fromhex(coap_layer.data.replace(':', ''))
            if payload:
                packet_list.append({
                    'time': timestamp,
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'src_port': packet.udp.srcport,
                    'dst_port': packet.udp.dstport,
                    'payload': payload.decode("utf-8", errors="ignore"),
                    'packet_size': packet_size,
                    'method': int(coap_layer.code)
                })
        except AttributeError:
            continue
    
    capture.close()
    return packet_list

def find_matching_packet(packet, packet_list):
    for pkt in packet_list:
        if pkt['payload'] == packet['payload']:
            return pkt
    return None

def calculate_metrics(file1, file2):
    packets1 = get_packets(file1)
    packets2 = get_packets(file2)
    latencies = []
    total_packet_sizes = []
    total_packets = len(packets1)
    matched_packets = 0
    packets_sent = 0
    packets_received = 0

    for pkt1 in packets1:
        pkt2 = find_matching_packet(pkt1, packets2)
        total_packet_sizes.append(pkt1['packet_size'])
        if pkt2:
            latency = (pkt2['time'] - pkt1['time']).total_seconds() * 1000 
            if latency > 0:
                latencies.append(latency)
                matched_packets += 1
        if pkt2['method'] == 2: # POST
            packets_sent += 1
            if pkt1['method'] == 69: # observe
                packets_received += 1

    jitter_values = [abs(latencies[i+1] - latencies[i]) for i in range(len(latencies)-1)]
    average_jitter = sum(jitter_values) / len(jitter_values) if jitter_values else 0

    total_data = sum(total_packet_sizes) 
    total_time = (packets1[-1]['time'] - packets1[0]['time']).total_seconds() 
    throughput = (total_data / total_time) * 8  # bits/s

    plr = (packets_sent - packets_received) / packets_sent * 100

    return latencies, average_jitter, throughput, plr

file1 = 'coap_post_single.pcap'
file2 = 'coap_get_single.pcap'

latencies, average_jitter, throughput, plr = calculate_metrics(file1, file2)

if latencies:
    average_latency = sum(latencies) / len(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)
    print(f'Average latency: {average_latency:.2f} ms')
    print(f'Min latency: {min_latency:.2f} ms')
    print(f'Max latency: {max_latency:.2f} ms')
    print(f'Average jitter: {average_jitter:.2f} ms')
    print(f'Throughput: {throughput:.2f} bps')
    print(f'Packet Loss Ratio: {plr:.2f} %')
else:
    print('No matching packets found.')
