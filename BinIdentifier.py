#!/usr/bin/python

import r2pipe
import os
import json
import md5
from collections import OrderedDict, Counter

CONTROL_BINS = {
    "722527-1993-USDM-SVX-EG33.bin" : None,
    "703243-1991-EDM-Legacy-EJ22.bin" : None,
    "74401A-1995-JDM-WrxRA-EJ20T.bin" : None
}

class Instruction:
    def __init__(self, base_addr, instruction):
        self.base_addr = hex(base_addr)

        params = instruction.split()
        self.opcode = params[0]
        self.params = params[1:]


class Block:
    def __init__(self, base_addr, seq_json):
        self.base_addr = hex(base_addr)
        self.seq_inst = OrderedDict()

        for op in seq_json:
            self.seq_inst[op['offset']] = Instruction(op['offset'], op['opcode'])

    def get_seq_inst(self, should_hash=True):
        """
        String representation of block instructions
        :param should_hash: Return hask of opcodes or not
        """
        opcodes = ""

        for instruction in self.seq_inst.values():
            opcodes = opcodes + "{}".format(instruction.opcode)

        return md5.new(opcodes).hexdigest() if should_hash else opcodes


class CFG:
    def __init__(self, json):
        self.json = json[0] if json else ""

        if 'offset' in self.json:
            self.base_addr = hex(json[0]['offset'])

            if 'blocks' in json[0]:
                blocks = json[0]['blocks']
                dict_block = {}

                # Create a dictionary of all blocks
                for blk in blocks:
                    dict_block[blk['offset']] = [Block(blk['offset'], blk['ops']), blk]

                # Match up all the block objects to their corresponding jump, fail addresses
                for key, pair in dict_block.items():
                    block_obj = pair[0]
                    block_json = pair[1]

                    if 'fail' in block_json:
                        try:
                            block_obj.fail = dict_block[block_json['fail']][0]
                        except KeyError:
                            continue

                    if 'jump' in block_json:
                        try:
                            block_obj.jump = dict_block[block_json['jump']][0]
                        except KeyError:
                            continue

                self.blocks = dict_block


class EcuFile:
    def __init__(self, file_name, r2):
        self.filename = filename

        split = file_name.split('/')
        name = split[len(split) - 1].split('-')
        self.name = name[0][4:] + '-' + name[1][2:] + '-' + name[4].split('.')[0]

        self.get_rvector_location(r2)
        self.get_rvector_calls(r2)

        healthcheck = Counter(self.rvector_jmps).most_common(1)
        self.healthcheck = healthcheck[0][0] if healthcheck else "?"

    def get_rvector_location(self, r2):
        """
        Get addr location of the reset vector
        """
        r2.cmd('s 0xfffe')
        location = r2.cmd('px0')[:4]

        self.rvector_location = location[2:4] + location[:2]

    def get_rvector_calls(self, r2):
        """
        Get all calls made in the reset vectors main loop
        """
        r2.cmd('s 0x{}'.format(self.rvector_location))
        r2.cmd('aa')

        # TODO: fix? Get 1000 instructions due to radare2 stopping too early with analysis
        instructions = json.loads(r2.cmd('pdj 1000').replace('\r\n', '').decode('utf-8', 'ignore'), strict=False, object_pairs_hook=OrderedDict)
        calls = []
        stores = 0
        watch = False

        for i, ins in enumerate(instructions):
            if not ins:
                continue

            split = ins['opcode'].split(' ')

            if not watch:
                if split[0] == 'STA':
                    stores += 1
                else:
                    stores = 0

                if stores >= 6:
                    watch = True
            else:
                if split[0] == 'JSR':
                    calls.append(split[1])
                elif len(calls) > 10:
                    r2.cmd("afu 0x{}".format(hex(ins['offset'])))
                    break
                else:
                    calls = []
                    continue

        self.rvector_calls = len(calls)
        self.rvector_jmps = calls

    def __str__(self):
        pass

def jaccard_index(list_1, list_2):
    """
    Calculate Jaccard index from two lists (Use shortest list as check)
    :param list_1, list_2: Lists to compare
    :returns: Jaccard index of list_1 & list_2
    """
    if len(list_1) < len(list_2):
        intersection = len([x for x in list_1 if x in list_2])
    else:
        intersection = len([x for x in list_2 if x in list_1])

    union = len(list_1) + len(list_2) - intersection

    return float(intersection) / union

def parse_bin(filename, r2):
    """
    Helper to parse a bin file and get the CFG for the reset vector
    :returns: EcuFile instance
    """
    r2.cmd('e asm.arch=m7700')
    r2.cmd('e anal.limits=true')
    r2.cmd('e anal.from=0x8000')
    r2.cmd('e anal.to=0xffd0')

    ecu = EcuFile(filename, r2)

    # Grab reset vector blocks
    ecu.rvector_cfg = CFG(json.loads(
        unicode(r2.cmd("agj"), errors='ignore'), strict=False, object_pairs_hook=OrderedDict
    ))
    hashes = []
    for offset, pair in ecu.rvector_cfg.blocks.items():
        hashes.append(pair[0].get_seq_inst())
    ecu.rvector_hashes = hashes

    # Grab healthcheck blocks
    r2.cmd("s 0x{}".format(ecu.healthcheck))
    r2.cmd("aa")
    ecu.healtcheck_cfg = CFG(json.loads(
        unicode(r2.cmd("agj"), errors='ignore'), strict=False, object_pairs_hook=OrderedDict
    ))
    hashes = []
    for offset, pair in ecu.healtcheck_cfg.blocks.items():
        hashes.append(pair[0].get_seq_inst())
    ecu.healthcheck_hashes = hashes

    r2.quit()

    return ecu

if __name__ == '__main__':
    clusters = {}

    # Setup control bins
    for filename, _ in CONTROL_BINS.items():
        r2 = r2pipe.open('./bins/' + filename)
        CONTROL_BINS[filename] = parse_bin(filename, r2)
        clusters[filename] = []

        print("Created control for {}".format(filename))

    # Setup unknown bins
    for filename_1 in os.listdir('./bins'):
        r2 = r2pipe.open('./bins/' + filename_1)
        ecu = parse_bin(filename_1, r2)

        highest_value = 0
        highest_control = None

        for filename_2, control in CONTROL_BINS.items():
            value = jaccard_index(ecu.rvector_hashes, control.rvector_hashes)

            if value > highest_value:
                highest_value = value
                highest_control = filename_2

        clusters[highest_control].append(filename_1)

        print("Parsed {}".format(filename_1))

    # Output clustering results
    for control, bins in clusters.items():
        print(control)

        for bin in bins:
            print("\t{}".format(bin))

    with open('clusters.json', 'w') as file:
        json.dump(clusters, file)
