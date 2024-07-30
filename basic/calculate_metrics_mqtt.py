import pyshark

def is_mqtt_publish(packet):
    mqtt_layer = packet.mqtt
    packet_type = int(mqtt_layer.msgtype)
    return packet_type == 3  # PUBLISH

def get_packets(file):
    capture = pyshark.FileCapture(file, display_filter='mqtt')
    packet_list = []
    
    for packet in capture:
        #if 'MQTT' in packet and is_mqtt_publish(packet):
        if 'MQTT' in packet:
            mqtt_layer = packet.mqtt
            try:
                raw_payload = mqtt_layer.msg
                packet_list.append({
                    'time': packet.sniff_time,
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'src_port': int(packet.tcp.srcport),
                    'dst_port': int(packet.tcp.dstport),
                    'payload': raw_payload,
                    'packet_size': int(packet.length),
                    'msg_type': int(packet.mqtt.msgtype)
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
        if pkt2['msg_type'] == 3:   # publish
            packets_sent += 1
            if pkt1['msg_type'] == 3:   # publish
                packets_received += 1

    jitter_values = [abs(latencies[i + 1] - latencies[i]) for i in range(len(latencies) - 1)]
    average_jitter = sum(jitter_values) / len(jitter_values) if jitter_values else 0

    total_data = sum(total_packet_sizes) 
    total_time = (packets1[-1]['time'] - packets1[0]['time']).total_seconds() 
    throughput = (total_data / total_time) * 8  # bits/s

    plr = (packets_sent - packets_received) / packets_sent * 100 if packets_sent else 100

    return latencies, average_jitter, throughput, plr

file1 = 'mqtt_sub_single.pcap'
file2 = 'mqtt_pub_single.pcap'

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
