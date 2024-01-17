from network import Protocol, DatagramSocket


class SampleDatagramSocket(DatagramSocket):
    """Socket class for SampleDatagramProtocol

    Subclasses of Socket can access the associated Protocol instance via the
    self.proto variable.
    """

    def __init__(self, *args, **kwargs):
        """Initializes a new socket.

        This constructor is called when creating a socket with socket().
        """

        super().__init__(*args, **kwargs)
        # Note: RDT may want to register sockets at a different point...
        self.proto.add_to_list(self)

    def input(self, data, src):
        self.deliver(data, src)

    def sendto(self, msg, dst):
        # SDP has no header, so message == segment
        self.output(msg, dst)


class SampleDatagramProtocol(Protocol):
    """
    Sample unreliable datagram protocol

    This class is intended only to demonstrate how to subclass Protocol,
    and it is of no practical use.  Rather than do any multiplexing, it creates
    a single datagram socket (per host) and passes it every datagram which
    arrives for this protocol.
    """

    PROTO_ID = 0xfd
    SOCKET_CLS = SampleDatagramSocket

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.socks = []

    # Helper method, specific to SDP
    def add_to_list(self, sock):
        self.socks.append(sock)

    def input(self, seg, src):
        """Called by the network layer when a packet arrives.

        Instead of multiplexing, SDP broadcasts every incoming segment to all
        SDP sockets.  Don't follow this example - RDT will pass segments only
        to the socket they belong to.
        """
        for s in self.socks:
            s.input(seg, src)
