# Take a database of crypt constants and output a database
# that is compatable with the FindCrypt plugin.
#
# Uses a database of constants from the FindCrypt repo.
#
# https://github.com/d3v1l401/FindCrypt-Ghidra/raw/master/findcrypt_ghidra/database.d3v
#
# This is based on the above script, but takes better
# advantage of Ghidra's features.
#@category Data.Crypt
#@author Torgo

from struct import unpack, pack
from StringIO import StringIO
from gzip import GzipFile

class CryptSignature(object):
    name = ''
    data = ''
    def __init__(self, name, data):
        self.name = name
        self.data = data

    def serialize(self):
        return pack(">I{}sbI{}s".format(len(self.name), len(self.data)), len(self.name), self.name, 0x0, len(self.data), self.data)

class CryptDatabase(object):
    path = None
    def __init__(self, path):
        self.path = path
        self.signatures = list()
        self.deserialize()

    def deserialize(self):
        self.signatures = list()
        with open(self.path, 'rb') as f:
            magic = f.read(4)
            if magic != b'\xD3\x01\x04\x01':
                raise Exception("Not a FindCrypt database. Incorrect magic : {}".format(magic))

            total_entries = unpack('>h', f.read(2))[0]
            for i in range(total_entries):
                name_size = unpack('>I', f.read(4))[0]
                name = unpack('{}s'.format(name_size), f.read(name_size))[0]
                compressed = unpack('>b', f.read(1))[0] == b'\x01'
                buff_size = unpack('>I', f.read(4))[0]
                buff = unpack('{}s'.format(buff_size), f.read(buff_size))[0]
                if compressed:
                    gzipped = StringIO(buff)
                    
                    # gzip decompress
                    gz = GzipFile(fileobj(gzipped))
                    buff = gz.read()
                self.signatures.append(CryptSignature(name=name, data=buff))

    def serialize(self, path):
        with open(path, 'wb') as f:
            f.write(b'\xD3\x01\x04\x01')
            f.write(pack('>h', len(self.signatures)))
            for sig in self.signatures:
                f.write(sig.serialize())

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('INPUT')
    parser.add_argument('OUTPUT')
    args = parser.parse_args()

    db = CryptDatabase(args.INPUT)
    db.serialize(args.OUTPUT)
