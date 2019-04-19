from struct import unpack

class CryptDatabase(object):
    path = None
    def __init__(self, path):
        self.path = path
        self.deserialize()

    def deserialize(self):
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
                    # gzip decompress
                    pass
                print("Unpacked: {} {} {}".format(name, compressed, len(buff)))

if __name__ == '__main__':
    db = CryptDatabase('database.d3v')
