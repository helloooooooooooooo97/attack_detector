"""TLS fingerprint helpers for the ML feature pipeline.

ja3_from_clienthello is extracted from framework/analyze.py so ml/ can use it
without depending on the rules-side analyzer.
"""


def ja3_from_clienthello(payload):
    """Compute JA3 from a TLS 1.2/1.3 ClientHello record payload."""
    if len(payload) < 5 or payload[0] != 1:
        return None
    msg_len = int.from_bytes(payload[1:4], "big")
    body = payload[4 : 4 + msg_len]
    if len(body) < 38:
        return None
    ver = int.from_bytes(body[0:2], "big")
    pos = 2 + 32
    if pos >= len(body):
        return None
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return None
    cs_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    ciphers = [
        int.from_bytes(body[i : i + 2], "big")
        for i in range(pos, min(pos + cs_len, len(body) - 1), 2)
    ]
    pos += cs_len
    if pos >= len(body):
        return None
    comp_len = body[pos]
    pos += 1 + comp_len

    extensions = {}
    if pos + 2 <= len(body):
        ext_total = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        end = min(pos + ext_total, len(body))
        while pos + 4 <= end:
            etype = int.from_bytes(body[pos : pos + 2], "big")
            elen = int.from_bytes(body[pos + 2 : pos + 4], "big")
            edata = body[pos + 4 : pos + 4 + elen]
            extensions[etype] = edata
            pos += 4 + elen

    groups = []
    if 10 in extensions:
        gdata = extensions[10]
        if len(gdata) >= 2:
            glen = int.from_bytes(gdata[:2], "big")
            groups = [
                int.from_bytes(gdata[2 + i : 4 + i], "big")
                for i in range(0, min(glen, len(gdata) - 2), 2)
            ]

    ecpf = []
    if 11 in extensions:
        ecpf = list(extensions[11][1:])

    return (
        f"{ver},"
        f"{'-'.join(map(str, ciphers))},"
        f"{'-'.join(map(str, sorted(extensions)))},"
        f"{'-'.join(map(str, groups))},"
        f"{'-'.join(map(str, ecpf))}"
    )
