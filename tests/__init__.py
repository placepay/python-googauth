import unittest
import googauth
import time

class TestFunctions(unittest.TestCase):
    """Test all googauth functions."""

    def test_generate_code(self):
        """Test :attr:`googauth.generate_code`."""
        secret_key = 'GBSWKZRYGVQWKMJR'
        value = googauth.generate_code(secret_key, 683753)
        self.assertTrue(value == '700446')

        secret_key = 'MYYDINDBMI2DSNBY'
        value = googauth.generate_code(secret_key, 282653)
        self.assertTrue(value == '060555')

        secret_key = googauth.generate_secret_key(8)
        for i in xrange(50000):
            value = googauth.generate_code(secret_key, i)
            self.assertTrue(len(value) == 6)

        secret_key = googauth.generate_secret_key(128)
        for i in xrange(50000):
            value = googauth.generate_code(secret_key, i)
            self.assertTrue(len(value) == 6)

    def test_verify_counter_based(self):
        """Test :attr:`googauth.verify_counter_based`."""
        secret_key = 'MUYDINLBG4ZWEYTF'
        value = googauth.verify_counter_based(secret_key, '343101', 957862)
        self.assertTrue(value == 957863)

        secret_key = 'MQZTOMLDHBRDOZDF'
        value = googauth.verify_counter_based(secret_key, '117316', 196831)
        self.assertTrue(value == 196834)

    def test_verify_time_based(self):
        """Test :attr:`googauth.verify_time_based`."""
        cur_time = int(time.time() / 30)
        secret_key = 'MQ3GEMTCMQ3TOOLG'
        code = googauth.generate_code(secret_key, cur_time)
        value = googauth.verify_time_based(secret_key, code)
        self.assertTrue(value == cur_time)

        cur_time = int(time.time() / 30)
        secret_key = 'G42DCMBQGJRGMZBQ'
        code = googauth.generate_code(secret_key)
        value = googauth.verify_time_based(secret_key, code)
        self.assertTrue(value != None)

    def test_generate_secret_key(self):
        """Test :attr:`googauth.generate_secret_key`."""
        value = googauth.generate_secret_key()
        self.assertTrue(len(value) == 16)

        value = googauth.generate_secret_key()
        self.assertTrue(len(value) == 16)

        for i in xrange(8, 129):
            value = googauth.generate_secret_key(i)
            self.assertTrue(len(value) == i)

        exception = None
        try:
            value = googauth.generate_secret_key(7)
        except TypeError, ex:
            exception = ex
        self.assertTrue(isinstance(exception, TypeError))

        exception = None
        try:
            value = googauth.generate_secret_key(129)
        except TypeError, ex:
            exception = ex
        self.assertTrue(isinstance(exception, TypeError))

    def test_get_otpauth_url(self):
        """Test :attr:`googauth.get_otpauth_url`."""
        secret_key = 'GYZTKMJSMZQWEMDF'
        value = googauth.get_otpauth_url('test', 'domain.com', secret_key)
        self.assertTrue(
            value == 'otpauth://totp/test@domain.com?secret=GYZTKMJSMZQWEMDF')

        secret_key = 'MMZDQMRTMU2WGNDB'
        value = googauth.get_otpauth_url('user', 'domain.com', secret_key)
        self.assertTrue(
            value == 'otpauth://totp/user@domain.com?secret=MMZDQMRTMU2WGNDB')

    def test_get_barcode_url(self):
        """Test :attr:`googauth.get_barcode_url`."""
        secret_key = 'MQ3DGYZQGYYTENTC'
        value = googauth.get_barcode_url('user', 'domain.com', secret_key)
        self.assertTrue(value == 'https://www.google.com/chart?chs=200x200' +
            '&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2Fuser%40domain.com' +
            '%3Fsecret%3DMQ3DGYZQGYYTENTC')

        secret_key = 'GQ4TQYJSHA2TCZTB'
        value = googauth.get_barcode_url('test', 'domain.com', secret_key)
        self.assertTrue(value == 'https://www.google.com/chart?chs=200x200' +
            '&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2Ftest%40domain.com' +
            '%3Fsecret%3DGQ4TQYJSHA2TCZTB')


if __name__ == '__main__':
    unittest.main()
