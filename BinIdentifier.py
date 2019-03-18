#!/usr/bin/python

import r2pipe
import os

rom_id_locations = {
    'eg33' : '0x8c3d',
    'ej15' : '0x73c4',
    'ej18' : '0xc8f1',
    'ej20T' : '0x8eb0',
    'ej20' : '0x4eb0',
    'ej22' : '0x8ddc'
}

class EcuFile:
    def __init__(self, file_name):
        r2 = r2pipe.open('./bins/' + file_name)
        r2.cmd('e asm.arch=m7700')
        r2.cmd('e anal.limits=true')
        r2.cmd('e anal.from=0x9000')
        r2.cmd('e anal.to=0xffff')

        for bin_type, location in rom_id_locations.items():
            r2.cmd('s {}'.format(location))

            if r2.cmd('px0')[:1] == '7':
                self.bin_type = bin_type
                break
        r2.quit()


if __name__ == '__main__':
    ecu_files = {}

    for filename in os.listdir('./bins'):
        ecu_files[filename] = EcuFile(filename)
        # ecu_files[filename].to_string()
