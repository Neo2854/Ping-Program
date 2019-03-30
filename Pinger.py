# Remember since ping uses ICMP this program must be run as a root user in UNIX and POSIX systems
# This code only works for python 3 and python 2

import argparse
import socket
import select
import struct
import time
import os

# Header parts of ICMP
Type = 8 # ECHO_REQUEST


# creating a Pinger class
class Pinger:

    # defining contructor
    def __init__(self,target,count,max_timeout,message):
        self.target = target
        self.count  = count

        # Making sure message is of even bytes
        if len(message)/2 != 0:
            message = message + ' '
        else:
            message = message

        self.message = bytes(message.encode('utf-8'))
        self.total_len = len(self.message) + 16

        # Keeping an eye on ICMP seq numbers
        self.seq    = 0

        # Getting IPv4 address of host
        self.addr = socket.gethostbyname(self.target)

        # max_timeout in seconds
        self.timeout = max_timeout

    def calc_checksum(self,packet):

        sum = 0

        # Number of 16-bit pairs
        max_count = (len(packet)/2)*2
        # Counting each added 16-bit digit using this variable
        count = 0
        while count < max_count:

            # Calculating value of 16-bit number by left shifting 8 times
            # Here it is done by multiplying with 2^8=256
            val = packet[count + 1] * 256 + packet[count]

            # For Python 2 Uncomment the below line and comment the above line
            # val = ord(source_string[count + 1])*256 + ord(source_string[count])
            sum += val
            # Just masking in case (;
            sum = sum & 0xfffffffff
            # Since 16 bits are 2 bytes
            count = count + 2

        # If packet contains odd number of bytes
        if max_count < len(packet):
            sum = sum + ord(packet[len(packet) - 1])
            sum= sum & 0xffffffff

        #Adding Carry back to sum
        sum = (sum >> 16) + (sum & 0xffff)
        # Incase we got carry after adding carry
        sum = sum + (sum >> 16)
        sum = ~sum
        sum = sum & 0xffff
        sum = (sum >> 8) | (sum << 8 & 0xff00)
        return sum

    def recv_pong(self,sock,ID,timeout):
        start_time = time.time()
        # System call select to check socket IO is readable or not
        readable = select.select([sock],[],[],timeout)
        time_taken = (time.time() - start_time)
        if readable[0] == []:
            return #Timed Out
        time_recv = time.time()
        reply,addr = sock.recvfrom(1024)

        # ICMP header id from 20 to 28 byte
        header = reply[20:28]
        typ,code,checksum,recv_ID,seq = struct.unpack('bbHHh',header)

        # Validating received Pong by comparing with our data
        if recv_ID == ID and seq == self.seq:
            # Calculating delay
            time_sent = struct.unpack('d',reply[28:36])[0]
            return time_recv - time_sent

        if timeout <= time_taken:
            print("Timed out Internal Error")
            return

    def send_ping(self,sock,ID):
        checksum = 0

        # For sending ping the ICMP header type is ECHO_REQUEST which is 8 and code is 0
        # Creating Header
        header = struct.pack('bbHHh',Type,0,checksum,ID,self.seq)

        # Creating data part only including time in data
        data = self.message
        data = struct.pack('d',time.time()) + data
        packet = header + data

        # Calculating Checksum
        checksum = self.calc_checksum(packet)
        header = struct.pack('bbHHh',Type,0,socket.ntohs(checksum),ID,self.seq)
        packet = header + data
        sock.sendto(packet,(self.addr,1))

    def ping_once(self):
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        except socket.error as err:
            if err.errno == 1:
                msg = "ICMP ping can only be sent as a root user"
                raise socket.error(msg)
        except Exception as ex:
            print("Error: {}".format(ex))

        # Process ID for unique Identifier in ICMP header
        ID = os.getpid() & 0xffff
        self.send_ping(sock,ID)
        delay = self.recv_pong(sock,ID,self.timeout)
        sock.close()
        return delay



    def ping(self):
        for i in range(self.count):
            print("Ping {} ({}) {} bytes of data.".format(self.target,self.addr,self.total_len))
            try:
                # Pinging once
                delay = self.ping_once()
            except socket.gaierror as err:
                print("Invalid hostname (socket error:{})".format(err))
                break

            if delay == None:
                print("Ping failed after timeout = {}".format(self.timeout))
            else:
                delay = delay*1000
                self.seq = self.seq + 1
                print("...Pong from {} ({}) icmp_seq={} time={}ms".format(self.target,self.addr,self.seq,delay))




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ping a Remote Host")
    parser.add_argument('target', action='store')
    parser.add_argument('-c', '--count', action='store', default=3, type=int, help="Number of pings to send")
    parser.add_argument('-t', '--timeout', action='store', default=5, type=int, help="MAX TIMEOUT in seconds")
    parser.add_argument('-m', '--message', action='store', default='', type=str, help="Message to be sent")
    args = parser.parse_args()
    pinger = Pinger(args.target, args.count, args.timeout,args.message)
    pinger.ping()