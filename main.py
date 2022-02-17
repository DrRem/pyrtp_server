import socket
import time
import math

file_ptr = open('resource/aaa.h264', 'rb')
h264 = file_ptr.read()
a = 0
b = 0


def byte_to_hex(byte_str):
    hex_str = ''
    for i in range(len(byte_str)):
        hex_str = hex_str + (hex(int(byte_str[i])))[2:].zfill(2)
    return hex_str


def get_nalu():  # 获取NALU
    global h264
    global a
    global b
    if a == 0:
        while True:
            temp = h264.find(b'\x00\x00', a)
            if h264.find(b'\x01', temp) == temp + 2:
                a = temp + 3
                break
            elif h264.find(b'\x01', temp) == temp + 3:
                a = temp + 4
                break
            else:
                a = temp + 1
        b = a
    while True:
        temp = h264.find(b'\x00\x00', b)
        if temp == -1:  # 切分结束
            return 0
        if h264.find(b'\x01', temp) == temp + 2:
            b = temp + 3
            flag = 3
            break
        elif h264.find(b'\x01', temp) == temp + 3:
            b = temp + 4
            flag = 4
            break
        else:
            b = temp + 1
    nalu_temp = h264[a:b - flag]
    a = b
    return nalu_temp


def generate_uf_packet(ufi, ufh, rbsp):
    F = str(format(ufi['F'], 'b').zfill(1))
    NRI = str(format(ufi['NRI'], 'b').zfill(2))
    Type = str(format(ufi['Type'], 'b').zfill(5))
    byte1 = format(int((F + NRI + Type), 2), 'x').zfill(2)
    S = str(ufh['S'])
    E = str(ufh['E'])
    R = str(ufh['R'])
    Type = str(format(ufh['Type'], 'b').zfill(5))
    byte2 = format(int((S + E + R + Type), 2), 'x').zfill(2)
    payload = byte1 + byte2 + rbsp
    return payload


def generate_rtp_packet(packet_vars):  # 封装单个RTP报文
    version = str(format(packet_vars['version'], 'b').zfill(2))
    padding = str(packet_vars['padding'])
    extension = str(packet_vars['extension'])
    csi_count = str(format(packet_vars['csi_count'], 'b').zfill(4))
    byte1 = format(int((version + padding + extension + csi_count), 2), 'x').zfill(2)
    marker = str(packet_vars['marker'])
    payload_type = str(format(packet_vars['payload_type'], 'b').zfill(7))
    byte2 = format(int((marker + payload_type), 2), 'x').zfill(2)
    sequence_number = format(packet_vars['sequence_number'], 'x').zfill(4)
    timestamp = format(packet_vars['timestamp'], 'x').zfill(8)
    ssrc = str(format(packet_vars['ssrc'], 'x').zfill(8))
    payload = packet_vars['payload']
    packet = byte1 + byte2 + sequence_number + timestamp + ssrc + payload
    return packet


def send_nalu(nalu_temp):
    global counter
    counter = counter + 1
    str_counter = str(counter).zfill(5)

    payload = byte_to_hex(nalu_temp)
    time_int = int(time.time())
    packet_vars = {'version': 2, 'padding': 0, 'extension': 0, 'csi_count': 0, 'marker': 1, 'payload_type': 96,
                   'sequence_number': counter, 'timestamp': time_int, 'ssrc': 185755418, 'payload': payload}
    # payload_type = 96 : H264
    header_hex = generate_rtp_packet(packet_vars)

    print('INFO:正在发送NALU(小)', str_counter, nalu_len_str)
    tcp_client.send(bytes.fromhex(header_hex))
    # 发送测量报文
    send_measurement_message()
    return 0


def send_nalu_big(nalu_temp):
    global counter
    counter = counter + 1
    # 解析NALU头部
    nalu_head = {}
    nalu_temp = byte_to_hex(nalu_temp)
    nalu_head_temp = nalu_temp[0:2]
    nalu_head_temp = int(nalu_head_temp, 16)
    nalu_head_temp = format(nalu_head_temp, 'b').zfill(8)
    nalu_head['F'] = int(nalu_head_temp[0], 2)
    nalu_head['NRI'] = int(nalu_head_temp[1:2], 2)
    nalu_head['Type'] = int(nalu_head_temp[3:], 2)
    # 测算分包数量
    nalu_temp = nalu_temp[2:]
    nalu_temp_len = len(nalu_temp)
    total_packages = math.ceil(nalu_temp_len / 2800)
    # 发送第一个报文
    rbsp = nalu_temp[:2800]
    ufi = {'F': nalu_head['F'], 'NRI': nalu_head['NRI'], 'Type': 28}  # Type = FU-A
    ufh_s = {'S': 1, 'E': 0, 'R': 0, 'Type': nalu_head['Type']}  # S = 1:NAL分片开始, E = 1:NAL分片结束
    ufh_n = {'S': 0, 'E': 0, 'R': 0, 'Type': nalu_head['Type']}
    ufh_e = {'S': 0, 'E': 1, 'R': 0, 'Type': nalu_head['Type']}
    payload = generate_uf_packet(ufi, ufh_s, rbsp)
    time_int = int(time.time())
    packet_vars = {'version': 2, 'padding': 0, 'extension': 0, 'csi_count': 0, 'marker': 0, 'payload_type': 96,
                   'sequence_number': counter, 'timestamp': time_int, 'ssrc': 185755418, 'payload': payload}
    # marker = 0 : 非结束报文
    str_counter = str(counter).zfill(5)
    print('INFO:正在发送NALU(大)', str_counter, nalu_len_str, 1)
    header_hex = generate_rtp_packet(packet_vars)
    tcp_client.send(bytes.fromhex(header_hex))
    # 发送测量报文
    send_measurement_message()
    for i in range(1, total_packages - 1):
        counter = counter + 1
        # 获取报文分片
        rbsp = nalu_temp[i * 2800:(i + 1) * 2800]
        payload = generate_uf_packet(ufi, ufh_n, rbsp)
        time_int = int(time.time())
        packet_vars = {'version': 2, 'padding': 0, 'extension': 0, 'csi_count': 0, 'marker': 0, 'payload_type': 96,
                       'sequence_number': counter, 'timestamp': time_int, 'ssrc': 185755418, 'payload': payload}
        str_counter = str(counter).zfill(5)
        print('INFO:正在发送NALU(大)', str_counter, nalu_len_str, i + 1)
        header_hex = generate_rtp_packet(packet_vars)
        tcp_client.send(bytes.fromhex(header_hex))
        # 发送测量报文
        send_measurement_message()
    # 发送最后一个报文
    counter = counter + 1
    rbsp = nalu_temp[(total_packages - 1) * 2800:]
    payload = generate_uf_packet(ufi, ufh_e, rbsp)
    time_int = int(time.time())
    packet_vars = {'version': 2, 'padding': 0, 'extension': 0, 'csi_count': 0, 'marker': 1, 'payload_type': 96,
                   'sequence_number': counter, 'timestamp': time_int, 'ssrc': 185755418, 'payload': payload}
    str_counter = str(counter).zfill(5)
    print('INFO:正在发送NALU(大)', str_counter, nalu_len_str, total_packages, 'FIN')
    header_hex = generate_rtp_packet(packet_vars)
    tcp_client.send(bytes.fromhex(header_hex))
    # 发送测量报文
    send_measurement_message()
    return 0


def send_measurement_message():
    # global measure_counter
    # measure_counter = measure_counter + 1
    # time_int = int(time.time())
    # payload = '0'.zfill(1400)  # 创建长度为1400的0串
    # packet_vars_1 = {'version': 2, 'padding': 0, 'extension': 0, 'csi_count': 0, 'marker': 1, 'payload_type': 108,
    #                  'sequence_number': measure_counter, 'timestamp': time_int, 'ssrc': 185755418, 'payload': payload}
    # measure_counter = measure_counter + 1
    # packet_vars_2 = {'version': 2, 'padding': 0, 'extension': 0, 'csi_count': 0, 'marker': 1, 'payload_type': 108,
    #                  'sequence_number': measure_counter, 'timestamp': time_int, 'ssrc': 185755418, 'payload': payload}
    # # payload类型设置为108 包对时间戳设置为相同
    # payload1 = generate_rtp_packet(packet_vars_1)
    # payload2 = generate_rtp_packet(packet_vars_2)
    # print('INFO:正在发送测量包对1')
    # tcp_client.send(bytes.fromhex(payload1))
    # time.sleep(0.05)  # 等待50ms
    # print('INFO:正在发送测量包对2')
    # tcp_client.send(bytes.fromhex(payload2))
    return 0


if __name__ == "__main__":
    tcp_server = socket.socket()
    tcp_server.bind(('0.0.0.0', 62610))
    tcp_server.listen(20)
    print("INFO:等待客户端")
    tcp_client, address = tcp_server.accept()
    print("INFO:客户端已连接", address)  # 与客户端建立连接
    counter = 0
    measure_counter = 0
    while True:
        nalu = get_nalu()
        if nalu == 0:
            print('INFO:视频流发送完毕！')
            # a = 0
            # b = 0  # 重播
            # counter = 0
            # continue
            break
        nalu_len = len(nalu)
        nalu_len_str = str(nalu_len).zfill(5)
        if nalu_len < 1400:
            send_nalu(nalu)
        else:
            send_nalu_big(nalu)
