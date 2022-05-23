import dpkt
import struct
import binascii

filename = 'assignment3_my_arp.pcap' #filename
file = open(filename, 'rb') #open the file
pcap = dpkt.pcap.Reader(file) #read the file
request = False #only accept a reply if we have seen a request
reply = False #similarly, we only want the first reply

for timestamp, buf in pcap:
    if(len(buf)<42 or len(buf)>60): #length of not 42 or 60 automatically disqualifies as an ARP message with Wireshark
        continue #also fixes issues of buffer not having 14 bytes
    if(struct.unpack(">H",buf[12:14])[0]==2054): #08*256+06=2054 and we want to change the endianness to print correctly
        if(len(buf)==42 and request==False): #a length of 42 implies request, so the first request will match with the first reply
            req_hardware_type = str(struct.unpack(">H",buf[14:16])[0])
            req_protocol_type = str(struct.unpack("H",buf[16:18])[0])
            req_hardware_size = str(struct.unpack(">B",buf[18:19])[0])
            req_protocol_size = str(struct.unpack(">B",buf[19:20])[0])
            req_op_code = str(struct.unpack(">H",buf[20:22])[0])
            req_src_ip = str(struct.unpack(">B",buf[28:29])[0]) + "." + str(struct.unpack(">B",buf[29:30])[0]) + "." + str(struct.unpack(">B",buf[30:31])[0]) + "." + str(struct.unpack(">B",buf[31:32])[0])
            req_dst_ip = str(struct.unpack(">B",buf[38:39])[0]) + "." + str(struct.unpack(">B",buf[39:40])[0]) + "." + str(struct.unpack(">B",buf[40:41])[0]) + "." + str(struct.unpack(">B",buf[41:42])[0])
            req_src_mac = str(hex(struct.unpack(">B",buf[22:23])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[23:24])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[24:25])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[25:26])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[26:27])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[27:28])[0]))[2:]
            req_dst_mac = str(hex(struct.unpack(">B",buf[32:33])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[33:34])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[34:35])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[35:36])[0])[2:]) + ":" + str(hex(struct.unpack(">B",buf[36:37])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[37:38])[0]))[2:]
            request = True
        if(len(buf)==60 and request==True and reply==False): #a length of 60 implies reply, must be after request and first reply; bootleg solution but works pretty well
            rep_hardware_type = str(struct.unpack(">H",buf[14:16])[0])
            rep_protocol_type = str(struct.unpack("H",buf[16:18])[0])
            rep_hardware_size = str(struct.unpack(">B",buf[18:19])[0])
            rep_protocol_size = str(struct.unpack(">B",buf[19:20])[0])
            rep_op_code = str(struct.unpack(">H",buf[20:22])[0])
            rep_src_ip = str(struct.unpack(">B",buf[28:29])[0]) + "." + str(struct.unpack(">B",buf[29:30])[0]) + "." + str(struct.unpack(">B",buf[30:31])[0]) + "." + str(struct.unpack(">B",buf[31:32])[0])
            rep_dst_ip = str(struct.unpack(">B",buf[38:39])[0]) + "." + str(struct.unpack(">B",buf[39:40])[0]) + "." + str(struct.unpack(">B",buf[40:41])[0]) + "." + str(struct.unpack(">B",buf[41:42])[0])
            rep_src_mac = str(hex(struct.unpack(">B",buf[22:23])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[23:24])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[24:25])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[25:26])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[26:27])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[27:28])[0]))[2:]
            rep_dst_mac = str(hex(struct.unpack(">B",buf[32:33])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[33:34])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[34:35])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[35:36])[0])[2:]) + ":" + str(hex(struct.unpack(">B",buf[36:37])[0]))[2:] + ":" + str(hex(struct.unpack(">B",buf[37:38])[0]))[2:]
            reply = True

print("ARP Request")
print("\tHardware Type: " + req_hardware_type)
print("\tProtocol Type: " + req_protocol_type)
print("\tHardware Size: " + req_hardware_size)
print("\tProtocol Size: " + req_protocol_size)
print("\tOperation Code: " + req_op_code)
print("\tSource IP: " + req_src_ip + "-> Destination IP: " + req_dst_ip)
print("\tSource MAC: " + req_src_mac + "-> Destination MAC: " + req_dst_mac)
print("ARP Reply")
print("\tHardware Type: " + rep_hardware_type)
print("\tProtocol Type: " + rep_protocol_type)
print("\tHardware Size: " + rep_hardware_size)
print("\tProtocol Size: " + rep_protocol_size)
print("\tOperation Code: " + rep_op_code)
print("\tSender MAC: " + rep_src_mac)
print("\tSender IP: " + rep_src_ip)
print("\tTarget MAC: " + rep_dst_mac)
print("\tTarget IP: " + rep_dst_ip)
