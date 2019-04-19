# Find crypt constants and label them
#
# Uses a database of constants from the FindCrypt repo.
#
# https://github.com/d3v1l401/FindCrypt-Ghidra/raw/master/findcrypt_ghidra/database.d3v
#
# This is based on the above script, but takes better
# advantage of Ghidra's features.
#@category Data.Crypt
#@author Torgo

from struct import unpack
from StringIO import StringIO
from gzip import GzipFile

class CryptSignature(object):
    name = ''
    data = ''
    def __init__(self, name, data):
        self.name = name
        self.data = data

    def serialize(self):
        return pack(">I{}sbI{}s", len(self.name), name, 0x0, len(self.data), data)

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
            print(magic)
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
            for sig in self.signatures:
                f.write(sig.serialize())
            

if __name__ == '__main__':
    db_path = str(askFile("Signature database", "Open findcrypt db"))
    db = CryptDatabase(db_path)

    monitor.setMessage("Scanning for crypt")
    monitor.initialize(len(db.signatures))
    for sig in db.signatures:
        monitor.checkCanceled()
        monitor.incrementProgress(1)
        found_addr = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), sig.data, None, True, monitor)
        if found_addr:
            print("Labelled {} @ {} - 0x{:x} bytes".format(sig.name, found_addr, len(sig.data)))
            createLabel(found_addr, sig.name, True)
