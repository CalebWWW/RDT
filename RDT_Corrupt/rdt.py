import queue
import threading
import random
import time
from network import StreamSocket, Protocol

# Reserved protocol number for experiments; see RFC 3692
IPPROTO_RDT = 0xfe

class RDTSocket(StreamSocket):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connected = False
        self.listener = False
        self.listeningQueue : queue.Queue
        self.destination :tuple[str, int]
        self.port = 0
        self.SequenceNumber = 0
        self.AckNumber = 0
        self.timeout = threading.Event()

    def bind(self, port):
        if self.connected:
            raise StreamSocket.AlreadyConnected
        self.port = port
        if self.port in self.proto.allAssignedPortNumbers or port in self.proto.allAvailibleSockets.keys():
            raise StreamSocket.AddressInUse
        self.proto.allAssignedPortNumbers.add(port)

    def listen(self):
        if self.port not in self.proto.allAssignedPortNumbers:
            raise StreamSocket.NotBound
        if self.connected:
            raise StreamSocket.AlreadyConnected
        self.listener = True
        self.listeningQueue = queue.Queue()
        with self.proto.availibleSocketsDictLock:
            self.proto.allAvailibleSockets.update({(self.port, 0, ''): self})

    def accept(self):
        if not self.listener:
            raise StreamSocket.NotListening
        while True:
            requestingSocketAddress = self.listeningQueue.get()
            if (self.port, requestingSocketAddress[1], requestingSocketAddress[0]) not in self.proto.allAvailibleSockets.keys():
                newSocket = self.createSocketPairInAccept(requestingSocketAddress)
                newSocket.sendConfirmation(True, True) #SYN ACK
                return (newSocket, newSocket.destination)

    def connect(self, addr):
        if self.port not in self.proto.allAssignedPortNumbers:
            self.assignPortNumber()
        if self.connected:
            raise StreamSocket.AlreadyConnected
        if self.listener:
            raise StreamSocket.AlreadyListening
        self.connected = True
        self.destination = addr
        with self.proto.availibleSocketsDictLock:
            self.proto.allAvailibleSockets.update({(self.port, self.destination[1], self.destination[0]): self})
        self.sendConfirmation(False, True) #SYN

    def send(self, data):
        if not self.connected:
            raise StreamSocket.NotConnected
        self.SequenceNumber += 1
        packet = Packet(self.port, self.destination[1], self.SequenceNumber, self.AckNumber, data)
        self.waitForAcknowlegement(packet.toBytes(), self.destination[0], packet)

#region helperMethods

    def sendConfirmation(self, Ack = False, Syn = False, recievedPacketSequenceNumber = 0):
        if not self.connected:
            raise StreamSocket.NotConnected
        if Syn and Ack:
            self.SequenceNumber += 1
        isAck = Ack and not Syn
        chosenSequenceNumber = recievedPacketSequenceNumber if isAck else self.SequenceNumber 
        packet = Packet(self.port, self.destination[1], chosenSequenceNumber, self.AckNumber, b'', Ack, Syn)
        if not isAck: #Does not resend try to resend ACK if there is a timeout
            self.waitForAcknowlegement(packet.toBytes(), self.destination[0], packet)
        else:
            self.output(packet.toBytes(), self.destination[0])

    def waitForAcknowlegement(self, data, destination, packet, bestAttemptAmount = 1000):
        self.timeout.clear()
        while True:
            self.output(data, destination)
            if bestAttemptAmount == 0 or self.timeout.wait(.01):
                #Last Sequence Number recieved is set in the protocol input
                if bestAttemptAmount == 0:
                    print(self.createPacketErrorMessage(packet))
                return
            bestAttemptAmount = bestAttemptAmount - 1

    def createPacketErrorMessage(self, packet):
        errorString = "\n timeout exceded: Ack Flag" if packet.isAckFlag else "timeout exceded:"
        return errorString + " SYN Flag \n" if packet.isSynFlag else errorString + "\n"

    def assignPortNumber(self):
        while(True):
            self.port = random.randrange(1025, 9000)
            if self.port not in self.proto.allAssignedPortNumbers:
                self.proto.allAssignedPortNumbers.add(self.port)
                return
    
    def createSocketPairInAccept(self, requestingSocketAddress):
        newSocket = RDTSocket(self.proto)
        newSocket.port = self.port
        newSocket.connected = True
        newSocket.listener = False
        newSocket.destination = requestingSocketAddress
        with self.proto.availibleSocketsDictLock:
            self.proto.allAvailibleSockets.update({(newSocket.port, newSocket.destination[1], newSocket.destination[0]): newSocket})
        return newSocket

#endregion

class RDTProtocol(Protocol):
    PROTO_ID = IPPROTO_RDT
    SOCKET_CLS = RDTSocket
    allAssignedPortNumbers :set
    allAvailibleSockets :dict #(local port, destination port, destination address), Socket
    lock :threading.Lock
    availibleSocketsDictLock :threading.Lock

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allAvailibleSockets = dict()
        self.allAssignedPortNumbers = set()
        self.lock = threading.Lock()
        self.availibleSocketsDictLock = threading.Lock()

    def input(self, seg, rhost):
        packet = Packet.toPacket(seg)
        
        if not packet.ConfirmChecksum():
            return 

        if packet.isSynFlag and packet.isAckFlag:
            recievingSocket = self.findRecievingSocket(packet, rhost)
            if self.isThisNewInformation(packet, recievingSocket):
                recievingSocket.timeout.set() #Relays that the Socket can stop waiting for the SYN
                recievingSocket.sendConfirmation(True, False, packet.sequenceNumber) #Sends the Ack
                #print("SYNACK Socket; Seq: " + str(recievingSocket.SequenceNumber) +" Ack: "+ str(recievingSocket.AckNumber))

        elif packet.isSynFlag:
            for socket in self.allAvailibleSockets.values():
                if socket.port == packet.destinationPort:
                    socket.listeningQueue.put((rhost, packet.sourcePort))
                    #SYN ACK sent in accept function
                    break

        elif packet.isAckFlag:
            recievingSocket = self.findRecievingSocket(packet, rhost)          
            if packet.sequenceNumber == recievingSocket.SequenceNumber:
                recievingSocket.timeout.set() #Relays that the Socket can stop waiting for the SYN ACK or sent information
            #print("Recieving Socket; Seq: " + str(recievingSocket.SequenceNumber) +" Ack: "+ str(recievingSocket.AckNumber))
            
        else:
            recievingSocket = self.findRecievingSocket(packet, rhost)
            if packet.sequenceNumber == recievingSocket.AckNumber + 1:
                recievingSocket.AckNumber += 1
                recievingSocket.deliver(packet.payload)
            recievingSocket.sendConfirmation(True, False, packet.sequenceNumber)
            #print("Sender Socket; Seq: " + str(recievingSocket.SequenceNumber) +" Ack: "+ str(recievingSocket.AckNumber))

    def findRecievingSocket(self, packet, rhost):
        while True:
            for key in self.allAvailibleSockets.keys():
                            if (key[0] == packet.destinationPort
                                and key[1] == packet.sourcePort
                                and key[2] == rhost):
                                    return self.allAvailibleSockets[key]
    
    def isThisNewInformation(self, packet, recievingSocket :RDTSocket):
        if packet.sequenceNumber == recievingSocket.AckNumber + 1:
            recievingSocket.AckNumber += 1
            return True #New information is recieved
        elif packet.sequenceNumber < recievingSocket.AckNumber + 1:
            return True #Resent Information
        return False #Out of order packet

class Packet():

    """
    Packet Formatting:
        Source Port take 3 bytes each,
        Destination Port take 3 bytes,
        Sequence Number: 4 bytes,
        Acknowlegement Number: 4 bytes,
        Checksum = 4 bytes,
        Flags takes 1 byte:
            Ack bit: 0000 0001
            Syn bit: 0000 0010
        Payload takes an undisclosed amount
    """

    def __init__(
            self, sourcePort :int, destinationPort :int, sequenceNumber :int, acknowlegementNumber :int, payload :bytes,
            isAckFlag :bool = False, isSynFlag :bool = False,
            ):
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.isAckFlag = isAckFlag
        self.isSynFlag = isSynFlag
        self.payload = payload
        self.sequenceNumber = sequenceNumber
        self.acknowlegementNumber = acknowlegementNumber
        self.checksum = self.CreateChecksum()

    def toBytes(self):
        byteResult = b''
        byteResult += self.sourcePort.to_bytes(3, "big")
        byteResult += self.destinationPort.to_bytes(3, "big")
        byteResult += self.sequenceNumber.to_bytes(4, "big")
        byteResult += self.acknowlegementNumber.to_bytes(4, "big")
        byteResult += self.checksum
        byteResult += self.CreateFlagByte([self.isAckFlag, self.isSynFlag])
        byteResult += self.payload
        return byteResult

    def toPacket(byteStream :bytes):
        sourcePort = int.from_bytes(byteStream[0:3], "big")
        destinationPort = int.from_bytes(byteStream[3:6], "big")
        sequenceNumber = int.from_bytes(byteStream[6:10], "big")
        acknowlegementNumber = int.from_bytes(byteStream[10:14], "big")
        checksum = byteStream[14:18]
        flagByte = byteStream[18:19:]
        isAckFlag = True if Packet.isBitSet(flagByte,1) > 0 else False
        isSynFlag = True if Packet.isBitSet(flagByte,2) > 0 else False
        payload = byteStream[19:]
        
        packet = Packet(sourcePort, destinationPort, sequenceNumber, acknowlegementNumber, payload, isAckFlag, isSynFlag)
        packet.checksum = checksum
        return packet

#region FlagHelperMethods

    def isBitSet(oneByte, pos): #LOOK INTO STATIC
        bit = int.from_bytes(oneByte, "big") >> pos - 1
        return True if bit & 1 > 0 else False

    def CreateFlagByte(self, flags):
        total = 0
        flags.reverse()
        for flag in flags:
            total = total << 1 | flag
        return total.to_bytes(1, "big")

#endregion

#region ChecksumHelperMethods

    def CreateChecksum(self):
        self.checksum= b''
        checksum = 0
        checksumData = self.toBytes()
        for byte in checksumData:
            checksum ^= byte
        return checksum.to_bytes(4, "big")
    
    def ConfirmChecksum(self):
        originalChecksum = self.checksum
        checksum = self.CreateChecksum()
        return checksum == originalChecksum

#endregion