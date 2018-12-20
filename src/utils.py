
def bytesToInt(bytes):
    return int(bytes.hex(), base = 16)

def intToBytes(intx):
    res = []
    while intx > 0:
        res.append(intx & 0xff)
        intx >>= 8
    res.reverse()
    return bytes(res)