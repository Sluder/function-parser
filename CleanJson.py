#!/usr/bin/python

import r2pipe
import json
from collections import OrderedDict

if __name__ == '__main__':
    ecu_files = OrderedDict()

    with open('file.json') as file:
        json_data = json.load(file, object_pairs_hook=OrderedDict)

        for bin in json_data:
            split = bin.split('/')
            filename = split[len(split) - 1]

            print('Parsing {}'.format(filename))

            r2 = r2pipe.open('./bins/' + filename)
            r2.cmd('e asm.arch=m7700')
            r2.cmd('e anal.limits=true')
            r2.cmd('e anal.from=0x9000')
            r2.cmd('e anal.to=0xffff')

            for address, hashes in json_data[bin].items():
                r2.cmd('s {}'.format(address))
                r2.cmd('af-')
                r2.cmd('aaa')
                r2.cmd('sf.')
                function_addr = r2.cmd('s')

                if function_addr in ecu_files.items():
                    ecu_files[function_addr].append(hashes)
                else:
                    ecu_files[function_addr] = hashes

            r2.quit()
    print(ecu_files)
