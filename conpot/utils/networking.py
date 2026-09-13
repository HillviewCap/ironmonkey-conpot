import socket
from datetime import datetime

from slugify import slugify


def sanitize_file_name(name, host, port):
    """
    Ensure that file_name is legal. Slug the filename and store it onto the server.
    This would ensure that there are no duplicates as far as writing a file is concerned. Also client addresses are
    noted so that one can verify which client uploaded the file.
    :param name: Name of the file
    :param host: host/client address
    :param port port/client port
    :type name: str
    """
    return (
        "("
        + host
        + ", "
        + str(port)
        + ")-"
        + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        + "-"
        + slugify(name)
    )


# py3 chr
def chr_py3(x):
    return bytearray((x,))


# convert a string to a byte string for the wire
def str_to_bytes(x):
    """Encode text to the bytes a protocol handler writes to its socket.

    UTF-8, not ASCII (Phase 2 step H10c). This was `.encode("ascii")`, and it
    is the root cause of the substation persona's start page never having
    been served: `command_responder.do_GET` sends the status line and the
    headers, THEN encodes the body here, so a single non-ASCII byte anywhere
    in an htdocs file raised `UnicodeEncodeError` after the client had
    already been promised a 200. The client saw a truncated body on a broken
    connection and the only trace was a traceback in the container log. The
    page shipped with an em dash and eight U+2022 bullets, so the persona's
    front door -- and the `/login` form the H4 credential capture depends on
    -- had never actually reached a client.

    It is a honeypot response path, so this must not raise on ANY input.
    `surrogateescape` first, so bytes that arrived through a
    `surrogateescape` decode go back out unchanged; `replace` as the last
    resort, because a mangled character in a decoy page is strictly better
    than a half-sent response. UTF-8 is a superset of ASCII, so every value
    that worked before is byte-identical now.
    """
    if isinstance(x, bytes):
        return x
    text = x if isinstance(x, str) else str(x)
    try:
        return text.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError:
        return text.encode("utf-8", errors="replace")


# https://www.bountysource.com/issues/4335201-ssl-broken-for-python-2-7-9
# Kudos to Eugene for this workaround!
def fix_sslwrap():
    # Re-add sslwrap to Python 2.7.9
    import inspect

    __ssl__ = __import__("ssl")

    try:
        _ssl = __ssl__._ssl
    except AttributeError:
        _ssl = __ssl__._ssl2

    def new_sslwrap(
        sock,
        server_side=False,
        keyfile=None,
        certfile=None,
        cert_reqs=__ssl__.CERT_NONE,
        ssl_version=__ssl__.PROTOCOL_SSLv23,
        ca_certs=None,
        ciphers=None,
    ):
        context = __ssl__.SSLContext(ssl_version)
        context.verify_mode = cert_reqs or __ssl__.CERT_NONE
        if ca_certs:
            context.load_verify_locations(ca_certs)
        if certfile:
            context.load_cert_chain(certfile, keyfile)
        if ciphers:
            context.set_ciphers(ciphers)

        caller_self = inspect.currentframe().f_back.f_locals["self"]
        return context._wrap_socket(sock, server_side=server_side, ssl_sock=caller_self)

    if not hasattr(_ssl, "sslwrap"):
        _ssl.sslwrap = new_sslwrap


def get_interface_ip(destination_ip: str):
    # returns interface ip from socket in case direct udp socket access not possible
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((destination_ip, 80))
    socket_ip = s.getsockname()[0]
    s.close()
    return socket_ip
