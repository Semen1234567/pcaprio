


def beautiful_hex(hex_data: str) -> str:
    res = []

    for i in range(0, len(hex_data), 32):
        row = hex_data[i:i+32]
        res.append(' '.join([row[i:i+2] for i in range(0, len(row), 2)]))
    
    return '\n'.join(res) + " "
