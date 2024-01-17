#!/usr/bin/env python3

import threading
import unittest
import random
import itertools
import base64
import sys
import time
import os.path

sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[0])))
from network import *
from rdt import *
from exthread import *

class BaseNetworkTest(unittest.TestCase):
    """Base class to simplify setting up network, sockets, and connections"""
    # Protocol to use
    PROTO = RDTProtocol
    # Provide defaults
    LOSS = 0.00
    PER = 0.00
    # List of client socket addresses (bound if port is not None)
    CLIENTS = []
    # List of listening socket addresses (port must be set)
    LISTEN = []
    # Map of connection names to (client index, server index) pairs
    CONNS = {}

    def _connect_clients(self, conns, tick):
        for n, (c, l) in conns.items():
            if c is None or l is None:
                continue
            tick.acquire()
            self.c[n].connect(type(self).LISTEN[l])

    def makeconns(self, conns):
        """Connect the sockets specified in conns, populating the s/l/c maps"""
        caddrs = type(self).CLIENTS
        laddrs = type(self).LISTEN
        tick = threading.Semaphore(value=0)
        with ExThread(target=self._connect_clients, args=(conns, tick)) as cthr:
            for n, (c, l) in conns.items():
                if l is not None:
                    self.l[n] = self.lsocks[laddrs[l]]
                if c is not None:
                    self.c[n] = self.csocks[c]
                if c is None or l is None:
                    continue
                tick.release()
                s, _ = self.l[n].accept()
                self.s[n] = s

    def setUp(self, conns=None):
        caddrs = type(self).CLIENTS
        laddrs = type(self).LISTEN
        if conns is None:
            conns = type(self).CONNS
        pid = type(self).PROTO.getid()

        # Create network and hosts
        n = Network(loss=type(self).LOSS, per=type(self).PER)
        self.h = {}
        # Use set comprehension to eliminate duplicates
        for ip in {fst for fst, _ in itertools.chain(caddrs, laddrs)}:
            h = Host(n, ip)
            h.register_protocol(type(self).PROTO)
            self.h[ip] = h

        # Create and set up listening sockets
        self.lsocks = {}
        for ip, port in laddrs:
            ls = self.h[ip].socket(pid)
            ls.bind(port)
            ls.listen()
            self.lsocks[ip, port] = ls

        # Create client sockets
        self.csocks = []
        for ip, port in caddrs:
            cs = self.h[ip].socket(pid)
            if port:
                cs.bind(port)
            self.csocks.append(cs)

        # Set up connections
        self.s = {}
        self.l = {}
        self.c = {}
        self.makeconns(conns)

    def test_00_connect(self):
        """Connection setup is successful"""
        pass

class A0_ErrorChecking(BaseNetworkTest):
    CLIENTS = [('10.50.254.1', None), ('10.50.254.1', None),
               ('10.50.254.2', None), ('10.50.254.2', None)]
    LISTEN = [('10.50.254.2', 3324), ('10.50.254.2', 26232)]
    CONNS = {'a': (0, None), 'b': (1, None), 'c': (2, None), 'd': (3, None), 'l': (None, 0)}

    def test_01_bind_namespace(self):
        """Different hosts can bind the same port number"""
        self.c['a'].bind(42533)
        self.c['c'].bind(42533)

    def test_02_bindinuse(self):
        """Bind can raise AddressInUse"""
        self.c['a'].bind(29539)
        with self.assertRaises(Socket.AddressInUse):
            self.c['b'].bind(29539)

    def test_03_bindinuse_listen(self):
        """Bind can raise AddressInUse for listening socket"""
        with self.assertRaises(Socket.AddressInUse):
            self.c['d'].bind(type(self).LISTEN[0][1])

    def test_04_bindafteraccept(self):
        """Bind cannot be called after accept"""
        self.makeconns({'x': (0, 0)})
        with self.assertRaises(StreamSocket.AlreadyConnected):
            self.s['x'].bind(23583)

    def test_05_bindafterconnect(self):
        """Bind cannot be called after connect"""
        self.makeconns({'x': (0, 0)})
        with self.assertRaises(StreamSocket.AlreadyConnected):
            self.c['x'].bind(29691)

    def test_06_listenafterconnect(self):
        """Listen cannot be called after connect"""
        self.makeconns({'x': (0, 0)})
        with self.assertRaises(StreamSocket.AlreadyConnected):
            self.c['x'].listen()

    def test_07_2connect(self):
        """Connect cannot be called twice on a socket"""
        self.makeconns({'x': (0, 0)})
        with self.assertRaises(StreamSocket.AlreadyConnected):
            self.c['x'].connect(type(self).LISTEN[1])

    def test_08_notbound(self):
        """Bind must be called before listen"""
        with self.assertRaises(StreamSocket.NotBound):
            self.c['d'].listen()

    def test_09_notlistening(self):
        """Listen must be called before accept"""
        self.c['c'].bind(13579)
        with self.assertRaises(StreamSocket.NotListening):
            self.c['c'].accept()

    def test_10_notconnected(self):
        """Socket must be connected to send"""
        self.c['c'].bind(9532)
        with self.assertRaises(StreamSocket.NotConnected):
            self.c['c'].send(b'test-notconnected')

    def test_11_connectafterlisten(self):
        """Connect cannot be called after listen"""
        with self.assertRaises(StreamSocket.AlreadyListening):
            self.l['l'].connect(type(self).LISTEN[1])

    def test_12_queueconns(self):
        """Multiple connections are queued at a listening socket"""
        self.c['a'].bind(2828)
        self.c['b'].bind(4646)
        self.c['c'].bind(8383)
        # "sleep" is not a valid synchronization technique... but in this case
        # there's no choice, since we'd need to signal inside connect
        with ExThread(target=self.c['a'].connect, args=(type(self).LISTEN[0],)):
            time.sleep(0.1)
            with ExThread(target=self.c['b'].connect, args=(type(self).LISTEN[0],)):
                time.sleep(0.1)
                with ExThread(target=self.c['c'].connect, args=(type(self).LISTEN[0],)):
                    time.sleep(0.2)
                    cs, (host, port) = self.l['l'].accept()
                    self.assertEqual(host, type(self).CLIENTS[0][0])
                    self.assertEqual(port, 2828)
                    cs, (host, port) = self.l['l'].accept()
                    self.assertEqual(host, type(self).CLIENTS[1][0])
                    self.assertEqual(port, 4646)
                    cs, (host, port) = self.l['l'].accept()
                    self.assertEqual(host, type(self).CLIENTS[2][0])
                    self.assertEqual(port, 8383)

class A1_Lossless_1x1(BaseNetworkTest):
    CLIENTS = [('192.168.10.1', None), ('192.168.10.2', None)]
    LISTEN = [('192.168.10.1', 26093), ('192.168.10.2', 2531)]
    CONNS = {'a': (0, None), 'b': (1, None)}

    def client_bindsrc(self):
        self.c['a'].bind(32901)
        self.c['a'].connect((type(self).CLIENTS[1][0], 9920))

    def test_01_bindsrc(self):
        """Binding a client socket sets the source address"""

        self.c['b'].bind(9920)
        self.c['b'].listen()
        with ExThread(target=self.client_bindsrc) as client:
            cs, (host, port) = self.c['b'].accept()
            self.assertEqual(host, type(self).CLIENTS[0][0])
            self.assertEqual(port, 32901)

    def test_02_oneway(self):
        """Data can be sent in one direction"""
        self.makeconns({'c': (0, 1)})
        for i in range(100):
            data = b'test-oneway' + str(i).encode()
            self.c['c'].send(data)
            self.assertEqual(self.s['c'].recv(), data)

    def test_03_otherway(self):
        """Data can be sent in the other direction"""
        self.makeconns({'c': (1, 0)})
        for i in range(100):
            data = b'test-otherway' + str(i).encode()
            self.c['c'].send(data)
            self.assertEqual(self.s['c'].recv(), data)

    def test_04_oneway_pcs(self):
        """Multiple pieces of data are made into one stream"""
        self.makeconns({'c': (0, 1)})
        for i in range(100):
            self.c['c'].send(b'')
            self.c['c'].send(b'test-onew')
            self.c['c'].send(b'')
            self.c['c'].send(b'ay-pcs' + str(i).encode())
            self.assertEqual(self.s['c'].recv(),
                             b'test-oneway-pcs' + str(i).encode())

    def test_05_twoway(self):
        """Data can be sent both directions over a connected socket"""
        self.makeconns({'c': (0, 1)})
        for i in range(100):
            data = b'test-twowayC->S' + str(i).encode()
            data2 = b'test-twowayS->C' + str(i).encode()
            self.c['c'].send(data)
            self.assertEqual(self.s['c'].recv(), data)
            self.s['c'].send(data2)
            self.assertEqual(self.c['c'].recv(), data2)

    def test_06_binary(self):
        """Binary data can be sent"""
        data = base64.b64decode(
                b'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKi' +
                b'ssLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVW' +
                b'V1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgY' +
                b'KDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6yt' +
                b'rq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2N' +
                b'na29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==')
        data2 = base64.b64decode(
                b'R0lGODlhFAAUAPZqAP/////5nf/4m//3m//2mv/0mP73m/72mv71mf70mP' +
                b'7zl/7zlv7ylf7xlf7xlP7wlP7vkv7ukf7ukP7tkf3wlP3ukv3ukf3tkf3s' +
                b'j/3rj/3rjv3qjf3pjP3nivzqjfzpjPzpi/zoi/znivznifzmivzmifzmiP' +
                b'zliPzkh/zjhvzjhfzihfzhg/vkhvvihfvihPvhhPvgg/vfgvvfgfvdgPvd' +
                b'f/vcf/vafPrcf/rafPrae/rZfPrXevrXefrWePrUdfrTdfnWefnUdvnUdf' +
                b'nSdfnSdPnRc/nQcvnQcfnPcPnNb/nNbvjQcfjPcfjOcPjNbvjMbPjLbfjL' +
                b'bPjKbPjKa/jJa/jJavjIafjHZ/jGaPfJaffIaffHZ/fGaPfGZ/fGZvfFZv' +
                b'fEZffCYvTDtvSfm+xrdm4AO1oAJlcAJjkAJgAAAMDAwAAAAAAAAAAAAAAA' +
                b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                b'AAAAAAACH5BAEAAGsALAAAAAAUABQAAAfLgGuCg2tqhoeEiYOGEBgYHSgy' +
                b'hoqChgMKCo6QKDU1k4RqA6IDEI0YkZ08P2qgAwEBmI2bNTyqrJUDlpeyh2' +
                b'o/v7eGAIaxGGoAw4Y/SazCyZmOx8jKSUqHyMOyHdLTP0rWasaHj5u9atXg' +
                b'KB2P5CiotL/fXYbu5vbn8oYy9WhoZv/90ghUowQLl2ad1PQ7w1CgQzVaDl' +
                b'bi4WlhQ4dp1Bi8VYiHQoZnxpAhU6aMGi4SFwFjKHKkSYMpF/m6h/KTIkPf' +
                b'lEQ8yJFSJXOUAgEAOw==')
        self.makeconns({'c': (0, 1)})
        for i in range(100):
            self.c['c'].send(data)
            self.s['c'].send(data2)
            self.assertEqual(self.s['c'].recv(), data,
                             'failed client->server iteration {}'.format(i))
            self.assertEqual(self.c['c'].recv(), data2,
                             'failed server->client iteration {}'.format(i))

    def client_stress(self, MIN, MAX, TOTAL, data):
        # Verify that the data comes in in the right amount/order
        count = 0
        while count < TOTAL - MAX:
            incoming = self.s['c'].recv(MAX)
            b = len(incoming)
            ofs = count % MAX
            self.assertEqual(incoming, data[ofs:ofs+b],
                             'in chunk starting with byte {}'.format(count))
            count += b

    def test_07_stress(self):
        """A lot of data can be sent and received"""
        self.makeconns({'c': (0, 1)})
        # Send 1 MB in random sizes of up to 1400 B
        MIN, MAX, TOTAL = 1, 1400, 2 ** 20
        data = b'0123456789' * (MAX // 5)
        with ExThread(target=self.client_stress, args=(MIN, MAX, TOTAL, data)) as cthr:
            count = 0
            while count < TOTAL - MAX:
                b = random.randint(MIN, MAX)
                ofs = count % MAX
                self.c['c'].send(data[ofs:ofs+b])
                count += b
            b = TOTAL - count
            ofs = count % MAX
            self.c['c'].send(data[ofs:ofs+b])

class A2_Lossless_SameHost(A1_Lossless_1x1):
    """Runs the Lossless 1x1 tests between two sockets on a single host"""
    CLIENTS = [('92.68.10.1', None), ('92.68.10.1', None)]

class A3_Lossless_1x2(BaseNetworkTest):
    CLIENTS = [('172.16.170.22', None), ('172.16.170.22', None)]
    LISTEN = [('172.16.170.111', 20956), ('172.16.170.3', 1255)]
    CONNS = {'a': (0, 0), 'b': (1, 1)}

    def test_01_mux(self):
        """Multiple client sockets can coexist on a host"""
        for i in range(100):
            self.c['a'].send(b'2test-')
            self.c['b'].send(b'_te')
            self.c['b'].send(b'st3-3mux_')
            self.c['a'].send(b'mux2')
            self.assertEqual(self.s['b'].recv(), b'_test3-3mux_',
                             'iteration {}'.format(i))
            self.assertEqual(self.s['a'].recv(), b'2test-mux2',
                             'iteration {}'.format(i))

            self.c['a'].send(b'test2/mux2')
            self.c['b'].send(b'///test-mux///3')
            self.assertEqual(self.s['b'].recv(), b'///test-mux///3',
                             'iteration {}'.format(i))
            self.assertEqual(self.s['a'].recv(), b'test2/mux2',
                             'iteration {}'.format(i))

class A4_Lossless_1x2_SameHost(A3_Lossless_1x2):
    """Runs the Lossless 1x2 tests between three sockets on a single host"""
    CLIENTS = [('16.24.32.48', None), ('16.24.32.48', None)]
    LISTEN = [('16.24.32.48', 10956), ('16.24.32.48', 11255)]

class A5_Lossless_2x1(BaseNetworkTest):
    CLIENTS = [('172.16.22.1', None), ('172.16.22.2', None)]
    LISTEN = [('172.16.22.3', 20063)]
    CONNS = {'a': (0, 0), 'b': (1, 0)}

    def test_01_oneway(self):
        """Server can distinguish data from different clients"""
        for i in range(100):
            self.c['a'].send(b'aaa-test2x1oneway-aaa')
            self.c['b'].send(b'bbb-test2x1oneway-bbb')
            self.assertEqual(self.s['a'].recv(), b'aaa-test2x1oneway-aaa',
                             'iteration {}'.format(i))
            self.assertEqual(self.s['b'].recv(), b'bbb-test2x1oneway-bbb',
                             'iteration {}'.format(i))
            self.c['a'].send(b'AAA-TEST2X1ONEWAY-AAA')
            self.c['b'].send(b'BBB-TEST2X1ONEWAY-BBB')
            self.assertEqual(self.s['b'].recv(), b'BBB-TEST2X1ONEWAY-BBB',
                             'iteration {}'.format(i))
            self.assertEqual(self.s['a'].recv(), b'AAA-TEST2X1ONEWAY-AAA',
                             'iteration {}'.format(i))

    def test_02_twoway(self):
        """Server can reply to different clients"""
        for i in range(100):
            self.c['a'].send(b'aaa-test2x1twoway-aaa')
            self.c['b'].send(b'bbb-test2x1twoway-bbb')
            self.s['a'].send(b'twoway_aaa_2x1')
            self.s['b'].send(b'twoway_bbb_2x1')
            self.assertEqual(self.s['a'].recv(), b'aaa-test2x1twoway-aaa',
                             'iteration {}'.format(i))
            self.assertEqual(self.c['a'].recv(), b'twoway_aaa_2x1',
                             'iteration {}'.format(i))
            self.assertEqual(self.s['b'].recv(), b'bbb-test2x1twoway-bbb',
                             'iteration {}'.format(i))
            self.assertEqual(self.c['b'].recv(), b'twoway_bbb_2x1',
                             'iteration {}'.format(i))

            self.c['a'].send(b'aaa-test2x1twoway-aaa')
            self.s['b'].send(b'twoway_bbb_2x1')
            self.s['a'].send(b'twoway_aaa_2x1')
            self.c['b'].send(b'bbb-test2x1twoway-bbb')
            self.assertEqual(self.s['b'].recv(), b'bbb-test2x1twoway-bbb',
                             'iteration {}'.format(i))
            self.assertEqual(self.c['b'].recv(), b'twoway_bbb_2x1',
                             'iteration {}'.format(i))
            self.assertEqual(self.c['a'].recv(), b'twoway_aaa_2x1',
                             'iteration {}'.format(i))
            self.assertEqual(self.s['a'].recv(), b'aaa-test2x1twoway-aaa',
                             'iteration {}'.format(i))

class A6_Lossless_2x1_SameHost(A5_Lossless_2x1):
    CLIENTS = [('8.8.4.4', None), ('8.8.4.4', None)]
    LISTEN = [('8.8.4.4', 20063)]

class A7_Lossless_ManyConns(BaseNetworkTest):
    CLIENTS = [('192.168.40.253', None) for i in range(1000)]
    LISTEN = [('192.168.40.253', 48000 + i) for i in range(10)]
    CONNS = {'{}->{}'.format(i, i % 10): (i, i % 10) for i in range(1000)}

class B1_Corrupt02_1x1(A1_Lossless_1x1):
    PER = 0.02
class B2_Corrupt02_SameHost(A2_Lossless_SameHost):
    PER = 0.02
class B3_Corrupt02_1x2(A3_Lossless_1x2):
    PER = 0.02
class B4_Corrupt02_1x2_SameHost(A4_Lossless_1x2_SameHost):
    PER = 0.02
class B5_Corrupt02_2x1(A5_Lossless_2x1):
    PER = 0.02
class B6_Corrupt02_2x1_SameHost(A6_Lossless_2x1_SameHost):
    PER = 0.02
class B7_Corrupt02_ManyConns(A7_Lossless_ManyConns):
    PER = 0.02

class C1_Corrupt05_1x1(A1_Lossless_1x1):
    PER = 0.05
class C2_Corrupt05_SameHost(A2_Lossless_SameHost):
    PER = 0.05
class C3_Corrupt05_1x2(A3_Lossless_1x2):
    PER = 0.05
class C4_Corrupt05_1x2_SameHost(A4_Lossless_1x2_SameHost):
    PER = 0.05
class C5_Corrupt05_2x1(A5_Lossless_2x1):
    PER = 0.05
class C6_Corrupt05_2x1_SameHost(A6_Lossless_2x1_SameHost):
    PER = 0.05
class C7_Corrupt05_ManyConns(A7_Lossless_ManyConns):
    PER = 0.05

class D1_Corrupt10_1x1(A1_Lossless_1x1):
    PER = 0.10
class D2_Corrupt10_SameHost(A2_Lossless_SameHost):
    PER = 0.10
class D3_Corrupt10_1x2(A3_Lossless_1x2):
    PER = 0.10
class D4_Corrupt10_1x2_SameHost(A4_Lossless_1x2_SameHost):
    PER = 0.10
class D5_Corrupt10_2x1(A5_Lossless_2x1):
    PER = 0.10
class D6_Corrupt10_2x1_SameHost(A6_Lossless_2x1_SameHost):
    PER = 0.10
class D7_Corrupt10_ManyConns(A7_Lossless_ManyConns):
    PER = 0.10

class E1_Lose02_1x1(A1_Lossless_1x1):
    LOSS = 0.02
class E2_Lose02_SameHost(A2_Lossless_SameHost):
    LOSS = 0.02
class E3_Lose02_1x2(A3_Lossless_1x2):
    LOSS = 0.02
class E4_Lose02_1x2_SameHost(A4_Lossless_1x2_SameHost):
    LOSS = 0.02
class E5_Lose02_2x1(A5_Lossless_2x1):
    LOSS = 0.02
class E6_Lose02_2x1_SameHost(A6_Lossless_2x1_SameHost):
    LOSS = 0.02
class E7_Lose02_ManyConns(A7_Lossless_ManyConns):
    LOSS = 0.02

class F1_Lose05_1x1(A1_Lossless_1x1):
    LOSS = 0.05
class F2_Lose05_SameHost(A2_Lossless_SameHost):
    LOSS = 0.05
class F3_Lose05_1x2(A3_Lossless_1x2):
    LOSS = 0.05
class F4_Lose05_1x2_SameHost(A4_Lossless_1x2_SameHost):
    LOSS = 0.05
class F5_Lose05_2x1(A5_Lossless_2x1):
    LOSS = 0.05
class F6_Lose05_2x1_SameHost(A6_Lossless_2x1_SameHost):
    LOSS = 0.05
class F7_Lose05_ManyConns(A7_Lossless_ManyConns):
    LOSS = 0.05

class G1_Lose10_1x1(A1_Lossless_1x1):
    LOSS = 0.10
class G2_Lose10_SameHost(A2_Lossless_SameHost):
    LOSS = 0.10
class G3_Lose10_1x2(A3_Lossless_1x2):
    LOSS = 0.10
class G4_Lose10_1x2_SameHost(A4_Lossless_1x2_SameHost):
    LOSS = 0.10
class G5_Lose10_2x1(A5_Lossless_2x1):
    LOSS = 0.10
class G6_Lose10_2x1_SameHost(A6_Lossless_2x1_SameHost):
    LOSS = 0.10
class G7_Lose10_ManyConns(A7_Lossless_ManyConns):
    LOSS = 0.10

class H1_Corrupt10Lose10_1x1(A1_Lossless_1x1):
    LOSS = 0.10
    PER = 0.10
class H2_Corrupt10Lose10_SameHost(A2_Lossless_SameHost):
    LOSS = 0.10
    PER = 0.10
class H3_Corrupt10Lose10_1x2(A3_Lossless_1x2):
    LOSS = 0.10
    PER = 0.10
class H4_Corrupt10Lose10_1x2_SameHost(A4_Lossless_1x2_SameHost):
    LOSS = 0.10
    PER = 0.10
class H5_Corrupt10Lose10_2x1(A5_Lossless_2x1):
    LOSS = 0.10
    PER = 0.10
class H6_Corrupt10Lose10_2x1_SameHost(A6_Lossless_2x1_SameHost):
    LOSS = 0.10
    PER = 0.10
class H7_Corrupt10Lose10_ManyConns(A7_Lossless_ManyConns):
    LOSS = 0.10
    PER = 0.10

if __name__ == '__main__':
     unittest.main()
