import unittest
from unittest.mock import patch
import core,main

class PublicSnapshotTests(unittest.TestCase):
    def test_default_transport_cannot_connect(self):
        with patch('socket.socket',side_effect=AssertionError('external_network_forbidden')):
            result=core.read_once(core.Material('FAKE-CANARY-TOKEN','FAKE-DEVICE','1'),core.Transport())
        self.assertEqual(result.outcome,'network_error')
    def test_vendor_material_is_not_present(self):
        self.assertTrue(core.signing_key().startswith(b'SYNTHETIC-'))
        headers=core.headers_for(core.Material('FAKE-CANARY-TOKEN','FAKE-DEVICE','1'),b'{}')
        self.assertTrue(headers['appid'].startswith('SYNTHETIC-'))
    def test_default_emulator_adapter_is_unavailable(self):
        with self.assertRaisesRegex(RuntimeError,'not_included'):main.execute_live()

if __name__=='__main__':unittest.main()
