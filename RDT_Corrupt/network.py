import sys
import os
import random
import threading
from queue import Queue


def _trialgen(prob):
    while True:
        yield random.random() < prob


def _hexdump(data):
    for ofs in range(0, len(data), 16):
        line = data[ofs:ofs+16]
        hex1 = ' '.join('%02x' % c for c in line[:8])
        hex2 = ' '.join('%02x' % c for c in line[8:])
        disp = ''.join(chr(c) if c in range(32, 128) else '.' for c in line)
        print('%08x  %-23s  %-23s  |%s|' % (ofs, hex1, hex2, disp),
              file=sys.stderr)
    print('%08x' % (len(data),), file=sys.stderr)


class Network:
    def __init__(self, loss=0.0, per=0.0, debug=None):
        if debug is None:
            debug = 'NET_DEBUG' in os.environ
        if not hasattr(loss, '__next__'):
            loss = _trialgen(loss)
        if not hasattr(per, '__next__'):
            per = _trialgen(per)
        self.hosts = {}
        self.loss = loss
        self.per = per
        self.debug = debug

    def attach(self, host, ip):
        if ip in self.hosts:
            raise ValueError("Address {} already exists on network"
                             .format(ip))
        self.hosts[ip] = host

    def tx(self, proto, data, src, dst):
        # Ensure all transmitted data is encoded to bytes
        if not isinstance(data, bytes):
            raise TypeError("Network can only send bytes, not {}"
                            .format(type(data).__name__))
        # TODO: add delay and reordering
        lose = next(self.loss)
        if self.debug:
            print('%s -> %s%s' % (src, dst, ' (LOST!)' if lose else ''),
                  file=sys.stderr)
            _hexdump(data)
        if not lose and dst in self.hosts:
            if next(self.per):
                pos = random.randint(0, len(data) - 1)
                byte = random.randint(0, 255)
                data = data[:pos] + bytes((byte,)) + data[pos+1:]
            self.hosts[dst].input(proto, data, src)
        return len(data)


# Handles:
#  - net_address
#  - map of id -> protocol
#  - register(socketclass)
#  - udt_sendto(proto, dst, seg)
#  - udt_rcv(proto, src, seg)
class Host:
    def __init__(self, net, ip):
        self.net = net
        self.ip = ip
        self.protos = {}
        self.net.attach(self, ip)
        self.test_sock = None

    def register_protocol(self, class_):
        pid = class_.getid()
        if pid in self.protos:
            if isinstance(self.protos[pid], class_):
                return
            raise ValueError("Protocol ID %d already registered to %s" %
                             (pid, type(self.protos[pid]).__name__))
        self.protos[pid] = class_(self)

    def socket(self, proto):
        return self.protos[proto].socket()

    def output(self, proto, data, dst):
        self.net.tx(proto, data, self.ip, dst)

    def input(self, proto, data, src):
        self.protos[proto].input(data, src)


class Socket:
    """Base class for sockets associated with a particular protocol"""

    class AddressInUse(Exception):
        """
        Exception raised when attempting to bind to a port that is already
        bound
        """

    def __init__(self, proto):
        """Initializes a new socket, associating it with a Protocol instance"""
        self.proto = proto

    def bind(self, port):
        """
        Binds the socket to a local port

        If the port is already in use by another socket on this host, then the
        method should raise Socket.AddressInUse.  If the socket is already
        connected, it should raise StreamSocket.AlreadyConnected.
        """
        raise NotImplementedError

    def output(self, seg, host):
        """
        Send a segment to the given destination host using the underlying
        network protocol
        """
        self.proto.output(seg, host)

    def input(self, seg, host):
        """
        Called by the protocol when it receives a segment from a source host
        and determines that it belongs to this particular socket.

        This method should handle any socket-level receive behavior such as
        sending acknowledgments, resetting timers, or updating sliding windows.
        """
        raise NotImplementedError


class DatagramSocket(Socket):
    """
    Base class for sockets with datagram semantics

    These sockets are connectionless, so the destination address must be given
    for each message, and the source is provided on receipt.  Individual
    messages are framed.
    """

    def __init__(self, *args, **kwargs):
        """Initializes a new datagram socket"""

        super().__init__(*args, **kwargs)
        self.msgs = Queue()

    def deliver(self, msg, addr):
        """Appends the given message to the application-layer queue"""

        self.msgs.put((msg, addr))

    def recvfrom(self, n=None):
        """
        Retrieves the next buffered message

        Returns a pair (msg, addr) providing both the message and the socket
        address of the source.
        """

        data, addr = self.msgs.get()
        if n is None:
            n = len(data)
        return data[:n], addr

    def sendto(self, msg, dst):
        raise NotImplementedError


class StreamSocket(Socket):
    """Base class for sockets with stream semantics"""

    # Custom exceptions
    class NotBound(Exception):
        """Exception raised when attempting to listen on an unbound socket"""

    class NotListening(Exception):
        """
        Exception raised when non-listening sockets are asked to do listen-y
        things
        """

    class AlreadyListening(Exception):
        """
        Exception raised when attempting to connect using a socket that is
        already listening
        """

    class NotConnected(Exception):
        """
        Exception raised when attempting to send on a stream socket which is
        not connected
        """

    class AlreadyConnected(Exception):
        """
        Exception raised when attempting to connect a stream socket which is
        already connected
        """

    # Constructor - subclasses should call using super() as seen here
    def __init__(self, *args, **kwargs):
        """Initializes a new stream socket"""

        super().__init__(*args, **kwargs)
        self.data = b''
        self.datamut = threading.Lock()

    # Provided methods (you should not override these)
    def deliver(self, data):
        """
        Passes message data (bytes) to the application layer

        This data will be appended to a socket buffer where the application can
        retrieve it later.
        """

        with self.datamut:
            self.data += data

    def recv(self, n=None):
        """
        Retrieves data from the stream buffer

        Returns n bytes or all currently buffered data, whichever is smaller.

        TODO: If buffer is empty, the method should block until more data is
        delivered.
        """

        with self.datamut:
            if n is None:
                n = len(self.data)
            data, self.data = self.data[:n], self.data[n:]
        return data

    # Abstract methods, to be overridden in subclasses
    def connect(self, addr):
        """
        Connects the socket to a remote socket address

        If the socket is not yet bound to a local port, the implementation
        should choose an unused port for this socket's local address.

        If the socket is already connected, this method should raise
        StreamSocket.AlreadyConnected.  If the socket is listening, it should
        raise StreamSocket.AlreadyListening.
        """
        raise NotImplementedError

    def listen(self):
        """
        Identifies the stream socket as a listening (server) socket and begins
        to listen for and queue incoming connections

        If the socket has not been bound to a local address on which to listen,
        this method should raise StreamSocket.NotBound.  If the socket is
        already connected, it should raise StreamSocket.AlreadyConnected.
        """
        raise NotImplementedError

    def accept(self):
        """
        Accepts a single incoming connection, waiting for one if there are none
        pending.

        Returns a pair (socket, (addr, port)) giving a socket that may be used
        to communicate with the connecting client, and the remote socket
        address.

        If this is called on a socket which is not listening, the method should
        raise StreamSocket.NotListening.
        """
        raise NotImplementedError

    def send(self, msg):
        """
        Sends the provided message data to the remote host

        This method is called by the application to send message data (bytes)
        over a connected socket.  It should handle any socket-level sending
        behavior, such as setting ARQ timers.

        If the socket is not connected, this should raise
        StreamSocket.NotConnected.
        """
        raise NotImplementedError


class Protocol:
    """
    Represents the implementation of a transport-layer protocol.

    Host-level transport features such as multiplexing should be implemented in
    subclasses of Protocol as needed.
    """

    # Integer ID for this protocol; override in a subclass
    PROTO_ID = -1
    # Class for this protocol's sockets; override in a subclass
    SOCKET_CLS = Socket

    def __init__(self, host):
        """Initialize a new instance of the protocol on the given host"""
        self.host = host

    @classmethod
    def getid(class_):
        """Return the integer ID assigned to this protocol"""
        return class_.PROTO_ID

    def socket(self):
        """Create a new socket using this protocol for transport"""
        return type(self).SOCKET_CLS(self)

    def output(self, seg, dst):
        """
        Passes a segment (bytes) to the network layer for transmission to the
        given destination host.
        """
        self.host.output(self.getid(), seg, dst)

    def input(self, seg, src):
        """
        Handles an incoming segment

        This method is called by the network-layer thread when a segment is
        received for this protocol, providing the segment data (bytes) and
        network-layer address of the source host.

        It should handle any protocol-level receive behavior such as
        demultiplexing and error detection, then pass the segment and source
        address to the correct socket for handling.
        """
        raise NotImplementedError
