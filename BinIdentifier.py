#!/usr/bin/python

import r2pipe
import os
from collections import OrderedDict

rom_id_locations = {
    'eg33' : '0x8c3d',
    'ej15' : '0x73c4',
    'ej18' : '0xc8f1',
    'ej20T' : '0x8eb0',
    'ej20' : '0x4eb0',
    'ej22' : '0x8ddc'
}

clusters = {}

class EcuFile:
    def __init__(self, file_name):
        r2 = r2pipe.open('./bins/' + file_name)
        r2.cmd('e asm.arch=m7700')
        r2.cmd('e anal.limits=true')
        r2.cmd('e anal.from=0x9000')
        r2.cmd('e anal.to=0xffff')

        self.get_id_location(r2)
        self.get_fvector_location(r2)
        self.get_8000_data(r2)

        r2.quit()

    def get_id_location(self, r2):
        for bin_type, location in rom_id_locations.items():
            r2.cmd('s {}'.format(location))
            id = r2.cmd('px0')

            if id[:1] == '7':
                self.rom_id = id[:6]
                self.bin_type = bin_type
                self.id_location = location
                break

    def get_fvector_location(self, r2):
        r2.cmd('s 0xfffe')
        location = r2.cmd('px0')[:4]

        self.fvector_location = location[2:4] + location[:2]

    def get_8000_data(self, r2):
        r2.cmd('s 0x8000')
        self.data_0x8000 = r2.cmd('px0')[:2]

    def to_string(self):
        return 'Type: {} .. ID: {} .. ID L: {} .. 0x8000: {}'.format(self.bin_type, self.rom_id, self.id_location, self.data_0x8000)

if __name__ == '__main__':
    ecu_files = {}

    for filename in os.listdir('./bins'):
        ecu = EcuFile(filename)

        if ecu.fvector_location not in clusters:
            clusters[ecu.fvector_location] = []
        clusters[ecu.fvector_location].append(ecu)

    for address, ecus in clusters.items():
        print(address)

        for ecu in ecus:
            print('\t' + ecu.to_string())
