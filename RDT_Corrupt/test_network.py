#!/usr/bin/env python3

import sys
import os.path
sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[0])))

from network import *

import unittest
import unittest.mock as mock

# Auxiliary helper classes for Socket/Protocol
class SC1(Socket): pass
class SC2(Socket): pass
class PC1(Protocol):
    PROTO_ID = 1
    SOCKET_CLS = SC1
    last_inst = None
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        type(self).last_inst = self
class EvilPC1(Protocol):
    PROTO_ID = 1
    SOCKET_CLS = SC1
class PC2(Protocol):
    PROTO_ID = 2
    SOCKET_CLS = SC2
    last_inst = None
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        type(self).last_inst = self

class A0_NetworkTest(unittest.TestCase):
    def setUp(self):
        self.n = Network()
        self.mh = mock.MagicMock(name='host 1', spec=Host)
        self.mh2 = mock.MagicMock(name='host 2', spec=Host)
        self.n.attach(self.mh, '192.168.10.1')
        self.n.attach(self.mh2, '192.168.10.2')

    def test_noop(self):
        self.mh.input.assert_not_called()
        self.mh2.input.assert_not_called()
        
    def test_badaddr(self):
        self.n.tx(8, b'test-badaddr', '192.168.10.1', '192.168.99.99')
        self.mh.input.assert_not_called()
        self.mh2.input.assert_not_called()

    def test_txnonbytes(self):
        with self.assertRaises(TypeError):
            self.n.tx('test-string', '192.168.10.1', '192.168.10.2')
        with self.assertRaises(TypeError):
            self.n.tx(6, '192.168.10.1', '192.168.10.2')
        with self.assertRaises(TypeError):
            self.n.tx([b'nope'], '192.168.10.1', '192.168.10.2')
        with self.assertRaises(TypeError):
            self.n.tx((3, b'nope'), '192.168.10.1', '192.168.10.2')
        with self.assertRaises(TypeError):
            self.n.tx({8: b'nope'}, '192.168.10.1', '192.168.10.2')

    def test_dupaddr(self):
        mh3 = mock.MagicMock(name='host 3', spec=Host)
        with self.assertRaises(ValueError):
            self.n.attach(mh3, '192.168.10.1')

    def test_onetx(self):
        self.n.tx(9, b'test-onetx', '192.168.10.1', '192.168.10.2')
        self.mh.input.assert_not_called()
        self.mh2.input.assert_called_once_with(9, b'test-onetx', '192.168.10.1')

    def test_twotx(self):
        self.n.tx(4, b'test-twotx1', '192.168.10.1', '192.168.10.2')
        self.n.tx(7, b'test-twotx2', '192.168.10.2', '192.168.10.1')
        self.mh.input.assert_called_once_with(7, b'test-twotx2', '192.168.10.2')
        self.mh2.input.assert_called_once_with(4, b'test-twotx1', '192.168.10.1')

    def test_multitx(self):
        for n in range(10):
            msg = b'test-multitx' + str(n).encode()
            msg2 = msg + msg
            self.n.tx(10 + n, msg, '192.168.10.1', '192.168.10.2')
            self.n.tx(20 + n, msg2, '192.168.10.2', '192.168.10.1')
            self.mh.input.assert_called_once_with(20 + n, msg2, '192.168.10.2')
            self.mh2.input.assert_called_once_with(10 + n, msg, '192.168.10.1')
            self.mh.reset_mock()
            self.mh2.reset_mock()

    def test_missedmsg(self):
        mh3 = mock.MagicMock(name='host 3', spec=Host)
        self.n.tx(2, b'test-missed', '192.168.10.1', '192.168.10.3')
        self.n.attach(mh3, '192.168.10.3')
        mh3.input.assert_not_called()

class A1_LossyNetworkTest(unittest.TestCase):
    def setUp(self):
        self.mh = mock.MagicMock(name='host', spec=Host)

    def _test_loss(self, pct):
        n = Network(loss=pct/100)
        n.attach(self.mh, '192.168.10.1')
        data = 'test-{}pct-loss'.format(pct).encode()
        for i in range(10000):
            n.tx(7, data, '192.168.10.2', '192.168.10.1')
        lost = 10000 - self.mh.input.call_count
        self.assertGreaterEqual(lost, 80 * pct, 'significantly < {}% loss'.format(pct))
        self.assertLessEqual(lost, 120 * pct, 'significantly > {}% loss'.format(pct))

    def test_10pct(self):
        self._test_loss(10)

    def test_50pct(self):
        self._test_loss(50)

    def test_90pct(self):
        self._test_loss(90)

class A2_ErrorNetworkTest(unittest.TestCase):
    def setUp(self):
        self.mh = mock.MagicMock(name='host', spec=Host)

    def _test_corruption(self, pct):
        pct = 10
        n = Network(per=pct/100)
        n.attach(self.mh, '192.168.11.11')
        corrupt = 0
        data = 'test-{}pct-errors'.format(pct).encode()
        for i in range(10000):
            n.tx(7, data, '192.168.22.22', '192.168.11.11')
            args, kwargs = self.mh.input.call_args
            if args[1] != data:
                corrupt += 1
        self.assertEqual(self.mh.input.call_count, 10000)
        self.assertGreaterEqual(corrupt, 80 * pct, 'significantly < {}% corruption'.format(pct))
        self.assertLessEqual(corrupt, 120 * pct, 'significantly > {}% corruption'.format(pct))

    def test_10pct(self):
        self._test_corruption(10)

    def test_50pct(self):
        self._test_corruption(50)

    def test_90pct(self):
        self._test_corruption(90)


class B_HostTest(unittest.TestCase):
    def setUp(self):
        self.mn = mock.MagicMock(name='network', spec=Network)
        self.h1 = Host(self.mn, '192.168.10.1')
        self.h2 = Host(self.mn, '192.168.10.2')

    def test_attach(self):
        self.mn.attach.assert_any_call(self.h1, '192.168.10.1')
        self.mn.attach.assert_any_call(self.h2, '192.168.10.2')

    def test_output(self):
        self.h1.output(4, b'test-output', '192.168.10.2')
        self.mn.tx.assert_called_once_with(4, b'test-output',
                '192.168.10.1', '192.168.10.2')
        self.mn.reset_mock()
        self.h1.output(1, b'test-outputself', '192.168.10.1')
        self.mn.tx.assert_called_once_with(1, b'test-outputself',
                '192.168.10.1', '192.168.10.1')
        self.mn.reset_mock()
        self.h2.output(9, b'test-output2', '192.168.10.1')
        self.mn.tx.assert_called_once_with(9, b'test-output2',
                '192.168.10.2', '192.168.10.1')

    def test_registerproto(self):
        self.h1.register_protocol(PC1)
        self.h1.register_protocol(PC2)

        s1 = self.h1.socket(1)
        s2 = self.h1.socket(2)
        self.assertIsInstance(s1, SC1)
        self.assertIsInstance(s2, SC2)

    def test_registeralready(self):
        self.h1.register_protocol(PC1)
        with self.assertRaises(ValueError):
            self.h1.register_protocol(EvilPC1)

    def test_registerdupok(self):
        self.h1.register_protocol(PC1)
        self.h1.register_protocol(PC1)

    def test_notregistered(self):
        self.h1.register_protocol(PC1)
        with self.assertRaises(KeyError):
            s = self.h1.socket(0)
        with self.assertRaises(KeyError):
            s = self.h1.socket(2)

class C_L3CommTest(unittest.TestCase):
    def setUp(self):
        self.n = Network()
        self.h = Host(self.n, '192.168.10.1')
        self.mh = mock.MagicMock(name='host', spec=Host)
        self.n.attach(self.mh, '192.168.10.2')

    def test_output(self):
        self.h.output(6, b'test-output3', '192.168.10.2')
        self.mh.input.assert_called_once_with(6, b'test-output3',
                '192.168.10.1')

class D_ProtocolTest(unittest.TestCase):
    def setUp(self):
        self.mh = mock.MagicMock(name='host', spec=Host)
        self.p = PC1(self.mh)

    def test_output(self):
        self.p.output(b'test-outputp', '192.168.10.2')
        self.mh.output.assert_called_once_with(1, b'test-outputp',
                '192.168.10.2')

class E_SocketTest(unittest.TestCase):
    def setUp(self):
        self.mp = mock.MagicMock(name='protocol', spec=Protocol)
        self.s = Socket(self.mp)

    def test_output(self):
        self.s.output(b'test-outputs', '192.168.10.3')
        self.mp.output.assert_called_once_with(b'test-outputs',
                '192.168.10.3')

class F_HalfL4CommTest(unittest.TestCase):
    def setUp(self):
        self.n = Network()
        self.h1 = Host(self.n, '192.168.10.1')
        self.h2 = Host(self.n, '192.168.10.2')
        self.h1.register_protocol(PC2)
        self.h2.register_protocol(PC2)
        self.p2 = PC2.last_inst
        self.p2.input = mock.MagicMock(name='input')
        self.s1 = self.h1.socket(2)

    def test_output(self):
        self.s1.output(b'test-output4', '192.168.10.2')
        self.p2.input.assert_called_once_with(b'test-output4',
                '192.168.10.1')

class G_DatagramSocketTest(unittest.TestCase):
    def setUp(self):
        self.p = mock.MagicMock(name='protocol', spec=Protocol)
        self.ds = DatagramSocket(self.p)

    def test_deliver(self):
        self.ds.deliver(b'hello', '192.168.10.2')
        self.ds.deliver(b' world', '192.168.10.2')

        self.assertEqual(self.ds.recvfrom(), (b'hello', '192.168.10.2'))

        self.ds.deliver(b'', '192.168.10.2')

        self.assertEqual(self.ds.recvfrom(), (b' world', '192.168.10.2'))
        self.assertEqual(self.ds.recvfrom(), (b'', '192.168.10.2'))

    def test_trunc(self):
        self.ds.deliver(b'1test-trunc-test-trunc', '192.168.10.1')
        self.ds.deliver(b'2test-trunc-test-trunc', '192.168.10.2')
        self.assertEqual(self.ds.recvfrom(100), (b'1test-trunc-test-trunc', '192.168.10.1'))
        self.assertEqual(self.ds.recvfrom(12), (b'2test-trunc-', '192.168.10.2'))

class H_StreamSocketTest(unittest.TestCase):
    def setUp(self):
        self.p = mock.MagicMock(name='protocol', spec=Protocol)
        self.ss = StreamSocket(self.p)

    def test_deliver(self):
        self.ss.deliver(b"hello")
        self.ss.deliver(b" world")

        self.assertEqual(self.ss.recv(3), b"hel")
        self.assertEqual(self.ss.recv(), b"lo world")

    def test_deliver_split(self):
        self.ss.deliver(b"hello")
        self.assertEqual(self.ss.recv(3), b"hel")

        self.ss.deliver(b" world")
        self.assertEqual(self.ss.recv(4), b"lo w")
        self.assertEqual(self.ss.recv(), b"orld")

if __name__ == '__main__':
    unittest.main()
