import socket
import struct
connected = False
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 2620))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            connected = True
            while True:
                data = conn.recv(1024)
                if not data:
                   break
                print(f"Received {data!r}")
                while (data):
                    data = data[4:]
                    msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL",data[:16])
                    print(f"Type {msg_type} Len {msg_len} flags 0x{flags:02x} seq {seq} pid {pid}")
                    msg = data[16:msg_len]
                    rtm_family, rtm_dst_len, rtm_src_len, rtm_tos, rtm_table, rtm_protocol, rtm_scope, rtm_type, rtm_flags = struct.unpack("=BBBBBBBBL",msg[:12])
                    print(f"Family {rtm_family} dst_len {rtm_dst_len} src_len {rtm_src_len} rtm_table {rtm_table} proto {rtm_protocol} rtm_type {rtm_type} flags 0x{rtm_flags:08x}")

                    msg = msg[12:]
                    while (msg):
                        rt_len, rta_type = struct.unpack("=HH", msg[:4])
                        if rt_len < 4 :
                            continue
                        print(f"Type {rta_type} Len {rt_len}")
                        # rta_type 1 is RTA_DST
                        if (rta_type == 1 and rt_len == 8):
                            ip, = struct.unpack(">L", msg[4:8])
                            print (f"RTA_DST ip 0x{ip:08x}")
                        if (rta_type == 5 and rt_len == 8):
                            ip, = struct.unpack(">L", msg[4:8])
                            print (f"RTA_GATEWAY ip 0x{ip:08x}")
                        if (rta_type == 4 and rt_len == 8):
                            oif, = struct.unpack("=L", msg[4:8])
                            print (f"RTA_OIF oif {oif}")
                        msg = msg[rt_len:]
                    data = data[msg_len:]
                    print(f">> NEXT {data!r}")
except KeyboardInterrupt:
    if connected:
       print ("Closing connection")
       conn.close()
