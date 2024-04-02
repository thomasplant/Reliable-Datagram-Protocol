#!/usr/bin/env python3
import select
import socket
from datetime import datetime, timedelta
import queue 
import sys
import re
from os.path import exists

#Shared helper functions
def check_input() -> None:
    if len(sys.argv) != 5 or not exists(sys.argv[3]) or not sys.argv[2].isdigit():
        print("Invialid use of Command")
        sys.exit()

#Processes all incoming packets
def parse_input(buf, udp_reciever, udp_sender) ->None:
 
    com = re.findall(rb"SYN|ACK|FIN|DAT|RST", buf.recv)
    payload = re.split(rb"SYN\n|ACK\n|FIN\n|DAT\n|RST\n", buf.recv)
    
    payload = payload[1:]

    for i in range(len(payload)):
        cur_pack = packet()
        cur_pack.command = com[i].decode()

        payload[i] = re.split(rb"\n\n", payload[i], maxsplit=1)
        headers = re.split(rb"\n", payload[i][0])
        
        cur_pack.payload = payload[i][1]

        for head in headers:
            ack = re.match(rb"Acknowledgment: (\d+)", head)
            win = re.match(rb"Window: (\d+)", head)
            seq = re.match(rb"^Sequence: (\d+)", head)
            plen = re.match(rb"Length: (\d+)", head)

            if ack:
                cur_pack.ack = int(ack.group(1))
            if win:
                cur_pack.window = int(win.group(1))
            if seq:
                cur_pack.sequence = int(seq.group(1))
            if plen:
                cur_pack.plen = int(plen.group(1))
   

        if len(cur_pack.payload) == cur_pack.plen:
            log("Recieve", cur_pack)
            if cur_pack.command == "ACK":
                udp_sender.rcv_ack(cur_pack)
            else:
                udp_reciever.rcv_data(cur_pack, buf)


    buf.recv = b""
            

#Handles all log printing
def log(way, pack):
    now = datetime.now()
    now = now.astimezone()
    if pack.command != "ACK":
        print(now.strftime("%a %b %d %X %Z %Y: ") + way + "; " + pack.command + "; Sequence: " + str(pack.sequence) + "; Length: " + str(pack.plen))
    
    else:
        print(now.strftime("%a %b %d %X %Z %Y: ") + way + "; " + pack.command + "; Acknowledgment: " + str(pack.ack) + "; Window: " + str(pack.window))

#Stores the send and recieve buffer
class buffers:
    def __init__(self) ->None:
        self.send = b""
        self.recv = b""

#Packets representing a RDP packet
class packet:
    def __init__(self) ->None:
        self.sequence = 0
        self.command = ""
        self.ack = 0
        self.window = 0
        self.plen = 0
        self.payload = "".encode()

#Sender
class sender:

    def __init__(self,buf, read) -> None:
        self.state = "close"
        self.buf = "".encode()
        self.buf = buf
        self.window = 0
        self.snd_una = 1
        self.snd_next = 1
        self.timeout = datetime.now()
        try:
            self.read = open(read, 'br')
        except:
            print("Invalid read file")
            sys.exit()

    #Returns current state
    def getstate(self):
        return self.state

    #Send Syn and update 
    def open(self):
        self.buf.send = self.buf.send + "SYN\nSequence: 0\nLength: 0\n\n".encode()
        self.state = "syn_sent"
        pack = packet()
        pack.command = "SYN"
        log("Send", pack)
    
    #Sends FIN and updates state
    def close(self):
        self.state = "fin_sent"
        self.buf.send = self.buf.send + ("FIN\nSequence: " + str(self.snd_next) + "\nLength: 0\n\n").encode()
        
        pack = packet()
        pack.command = "FIN"
        pack.sequence = self.snd_next
        log("Send", pack)

    #Checks if there is timeout then resends
    def check_timeout(self):
        now = datetime.now()
        if (now-self.timeout) > timedelta(milliseconds=200):
            self.snd_next = self.snd_una
            self.send()
            self.timeout = datetime.now()

    #Process Ack
    def rcv_ack(self, pack):
        if self.state == "fin_sent":
            if pack.ack == self.snd_next +1:
                self.state = "close"
                
        if self.state == "open":
            self.window = pack.window
            if self.snd_una != pack.ack:
                self.timeout = datetime.now()
                self.snd_una = pack.ack

            self.send()
            
        if self.state == "syn_sent":
            if pack.ack == 1:
                self.window = pack.window
                self.state = "open"
                self.send()
   
    #Processes and Sends Packet
    def send(self):
        if self.state == "syn_sent":
            self.open()
           
        if self.state == "open":
            while self.window - (self.snd_next - self.snd_una) > 0 and self.state == "open":
                snd_win = self.window - (self.snd_next - self.snd_una)
                snd_win = min(1024, snd_win)
                self.read.seek(self.snd_next-1)
                payload = self.read.read(snd_win)
                if len(payload) == 0:
                    if self.snd_una == self.snd_next:
                        self.close()
                    else:
                        break
                else:
                    snd_pack = ("DAT\nSequence: " + str(self.snd_next) + "\nLength: " + str(len(payload)) + "\n\n").encode()
                    
                    pack = packet()
                    pack.command = "DAT"
                    pack.sequence = self.snd_next
                    pack.plen = len(payload)
                    log("Send", pack)
                    
                    self.buf.send = self.buf.send + snd_pack + payload
                    self.snd_next = self.snd_next + len(payload)
                    
        if self.state == "fin_sent":
            self.close()


#Reciever
class reciever:

    def __init__(self, send_buf, write) -> None:
        self.state = "close"
        self.buf = ""
        self.window = 4096
        self.send_buf = send_buf
        self.expc = 1
        self.out_of_order = {}
        try:
            self.write = open(write, 'bw')
        except:
            print("invalid write file")
            sys.exit()

    #returns reciever state
    def getstate(self):
        return self.state

    #All DAT, SYN, FIN, RST get processed
    def rcv_data(self,pack, buf):

        if pack.command == "SYN":
            if pack.command == "SYN":
                self.sendACK(pack.sequence + 1,buf)
                self.state = "open"
          
        if pack.command == "FIN":
            self.sendACK(pack.sequence +1, buf)
            self.state = "close"
               
        if self.state == "open":
            if pack.sequence == self.expc:
                self.write.write(pack.payload)
                self.expc = self.expc + pack.plen
        

            self.sendACK(self.expc, buf)

    #Sends return ACK
    def sendACK(self,number, buf):
        pack = packet()
        pack.command = "ACK"
        pack.ack = number
        pack.window = self.window
        log("Send", pack)
        
        buf.send = buf.send + ("ACK\nAcknowledgment: " + str(number) + "\nWindow: " + str(self.window) + "\n\n").encode()
        


def main():
    #Check input and declare echo server
    check_input()
    h2 = ("10.10.1.100", 8888)


    #set up the server
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    udp_sock.setblocking(False)
    udp_sock.bind((sys.argv[1], int(sys.argv[2])))

    #set up reciever and sender 
    buf = buffers()
    udp_sender = sender(buf, sys.argv[3])
    udp_reciever = reciever(buf, sys.argv[4])

    #Server is going to be in syn sent before it enters while lool
    udp_sender.open()

    while (udp_sender.getstate() != "close"):

        readable, writable, exceptional = select.select([udp_sock], [udp_sock], [udp_sock], 10)

        if udp_sock in readable:
            data = udp_sock.recv(5120)
            if data:
                buf.recv += data
                parse_input(buf,udp_reciever, udp_sender)

        if udp_sock in writable and not buf.send == b"" :
            bytes_sent = udp_sock.sendto(buf.send, h2)
            buf.send = buf.send[bytes_sent:]
        
        if udp_sock in exceptional:
            sys.exit()

        udp_sender.check_timeout()

    udp_sender.read.close()
    udp_reciever.write.close()


main()
