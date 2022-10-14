


def beautiful_hex(hex_data: str) -> str:
    res = []

    for i in range(0, len(hex_data), 32):
        row = hex_data[i:i+32]
        res.append(' '.join([row[i:i+2] for i in range(0, len(row), 2)]))
    
    return '\n'.join(res) + " "


def repr_IPv4(raw: bytes) -> str:
    return '.'.join([f'{b}' for b in raw])


def repr_IPv6(raw: bytes) -> str:
    res = []

    for i in range(0, len(raw), 2):
        part = f'{raw[i]:02x}{raw[i+1]:02x}'
        res.append(part)
    return ':'.join(res)
