import os
import subprocess
import sys

import broker
import django
from django.test import Client, TestCase

from brokerd import build as build_brokerd
from brokerd import run_brokerd


class ZeekTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        comm_zeek = os.path.join(sys.prefix, 'zeek_scripts',
                                 'communication.zeek')
        if not os.path.exists(comm_zeek):
            build_brokerd.render(comm_zeek)

        django.setup()
        run_brokerd.bind_port = 47000
        run_brokerd.setup()
        super(ZeekTestCase, cls).setUpClass()

    def setUp(self):
        self.zeek_proc = subprocess.Popen(
            ['zeek', os.path.join(sys.prefix, 'zeek_scripts')])
        self.c = Client()

    def tearDown(self):
        self.zeek_proc.terminate()
        self.zeek_proc.wait(1)


class ZeekInitializationTestCase(ZeekTestCase):
    def test_zeek_connected_to_brokerd(self):
        self.assertIsNone(self.zeek_proc.returncode, "Error starting Zeek")

        result = None
        max_time = 5
        for i in range(0, max_time):
            result = run_brokerd.subscriber.get(1, 1)
            if result and len(result) > 0:
                break

        self.assertIsNotNone(result, "brokerd got no message from Zeek")


class ZeekImportNativeTypesTestCase(ZeekTestCase):
    def setUp(self):
        self.zeek_proc = subprocess.Popen(
            ['zeek', os.path.join(sys.prefix, 'zeek_scripts'),
             'test_export_import.zeek'])
        self.c = Client()

    def test_zeek_connected_to_brokerd(self):
        self.assertIsNone(self.zeek_proc.returncode, "Error starting Zeek")

        while True:
            result = None
            max_time = 5
            for i in range(0, max_time):
                result = run_brokerd.subscriber.get(1, 1)
                if result:
                    break

            if not result:
                return
            t, msg = result[0]
            ev = broker.zeek.Event(msg)
            print(ev.name())
