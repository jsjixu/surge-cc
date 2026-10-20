import subprocess
import unittest
from unittest.mock import Mock

from test_core import config
from surge_cc.core import listener_is_surge, local_proxy_check


def completed(output, code=0):
    return subprocess.CompletedProcess([], code, output, "")


class ListenerTests(unittest.TestCase):
    def test_exact_port_and_actual_surge_binary(self):
        runner = Mock(side_effect=[
            completed("p42\ncSurge\nf21\nn127.0.0.1:6152\n"),
            completed("/Applications/Surge.app/Contents/MacOS/Surge\n"),
        ])
        self.assertTrue(listener_is_surge(config(), runner))
        self.assertEqual(runner.call_args_list[1].args[0], ["/bin/ps", "-p", "42", "-o", "comm="])

    def test_wrong_binary_even_if_named_surge(self):
        runner = Mock(side_effect=[
            completed("p42\ncSurge\nn127.0.0.1:6152\n"),
            completed("/Applications/Other.app/Contents/MacOS/Surge\n"),
        ])
        self.assertFalse(listener_is_surge(config(), runner))

    def test_missing_wrong_address_multiple_or_unreadable_listener(self):
        for output in (
            "", "p42\nn192.0.2.5:6152\n",
            "p42\nn127.0.0.1:6152\np43\nn*:6152\n",
            "n127.0.0.1:6152\n",
        ):
            with self.subTest(output=output):
                runner = Mock(return_value=completed(output))
                self.assertFalse(listener_is_surge(config(), runner))
                self.assertEqual(runner.call_count, 1)

    def test_ps_failure_and_timeout_block(self):
        for result in (completed("", 1), subprocess.TimeoutExpired("ps", 5)):
            runner = Mock(side_effect=[completed("p42\nn127.0.0.1:6152\n"), result])
            self.assertFalse(listener_is_surge(config(), runner))

    def test_wrong_owner_blocks_before_network_request(self):
        runner = Mock(return_value=completed("", 1))
        self.assertFalse(local_proxy_check(config(), runner)[0])
        self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
