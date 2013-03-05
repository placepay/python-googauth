import hashlib
import os
import base64
import urllib

def _generate_random_bytes():
    """Generate random bytes.

    Returns:

    Random bytes from sha512 hash.
    """
    # Generate sha1 hash of 8192 random bytes
    sha_hash = hashlib.sha512()
    sha_hash.update(os.urandom(8192))
    byte_hash = sha_hash.digest()

    # Rehash
    for i in xrange(6):
        sha_hash = hashlib.sha512()
        sha_hash.update(byte_hash)
        byte_hash = sha_hash.digest()
    
    return byte_hash

def generate_secret_key(length=16):
    """Generate random 16 character base 32 secret key.

    Arguments:

    .. csv-table::
        :header: "argument", "type", "value"
        :widths: 7, 7, 40

        "*length*", "string", "Length of secret key, min 8, max 128."

    Returns:

    Random 16 character base 32 secret key.

    Usage::

        import googauth
        print googauth.generate_secret_key()
    """
    if length < 8 or length > 128:
        raise TypeError('Secret key length is invalid.')

    byte_hash = _generate_random_bytes()
    if length > 102:
        byte_hash += _generate_random_bytes()

    return base64.b32encode(byte_hash)[:length]

def get_otpauth_url(user, domain, secret_key):
    """Generate otpauth url from secret key.

    Arguments:

    .. csv-table::
        :header: "argument", "type", "value"
        :widths: 7, 7, 40

        "*user*", "string", "User."
        "*domain*", "string", "Domain."
        "*secret_key*", "string", "Base 32 secret key."

    Returns:

    Otpauth url.

    Usage::

        import googauth
        secret_key = googauth.generate_secret_key()
        print googauth.get_otpauth_url('user', 'domain.com', secret_key)
    """
    return ('otpauth://totp/' + user + '@' + domain +
              '?secret=' + secret_key)

def get_barcode_url(user, domain, secret_key):
    """Generate a url to a QR barcode image from secret key using Google chart
    API.

    Arguments:

    .. csv-table::
        :header: "argument", "type", "value"
        :widths: 7, 7, 40

        "*user*", "string", "User."
        "*domain*", "string", "Domain."
        "*secret_key*", "string", "Base 32 secret key."

    Returns:

    QR barcode image url.

    Usage::

        import googauth
        secret_key = googauth.generate_secret_key()
        print googauth.get_barcode_url('user', 'domain.com', secret_key)
    """
    url = 'https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&'

    # Get otpauth url
    otp_url = get_otpauth_url(user, domain, secret_key)

    # Encode otp url
    url += urllib.urlencode({'chl': otp_url})

    return url
