import logging
import unittest

from donpapi.lib.logger import DonPAPIAdapter


class DonPAPIAdapterTest(unittest.TestCase):
    def test_debug_works_with_logger_adapter_state(self):
        adapter = DonPAPIAdapter()
        adapter.logger.setLevel(logging.DEBUG)
        adapter.logger.propagate = False
        # Python 3.13's LoggerAdapter.process() reads merge_extra, which is
        # only initialised by LoggerAdapter.__init__().
        adapter.debug('Targets: test')


if __name__ == '__main__':
    unittest.main()
