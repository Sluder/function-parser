#!/usr/bin/python

import r2pipe
import os
import json
import hashlib
from collections import OrderedDict

# Full path to binary directory
BIN_DIR = './test_bins'

class Instruction:
    def __init__(self, base_addr, instruction):
        self.base_addr = hex(base_addr)

        operands = instruction.split()
        self.opcode = operands[0]
        self.operands = operands[1:]


class Block:
    def __init__(self, base_addr, instruction_js):
        self.base_addr = hex(base_addr)
        self.parents = []
        self.instructions = OrderedDict()

        # Create instructions for ones in this block
        for inst in instruction_js:
            self.instructions[inst['offset']] = Instruction(inst['offset'], inst['opcode'])

    def get_opcodes(self, should_hash=True):
        """
        String representation of block instructions
        :param should_hash: Whether opcodes should be MD5 hashed
        """
        opcodes = ""

        for instruction in self.instructions.values():
            opcodes = opcodes + str(instruction.opcode)

        if should_hash:
            return hashlib.md5(opcodes.encode()).hexdigest()
        return opcodes


class Cfg:
    def __init__(self, fcn_json):
        """
        :param fcn_json: Function json pulled from radare
        """
        self.json = fcn_json[0] if fcn_json else ""
        self.first = None

        if 'offset' in self.json:
            self.base_addr = hex(self.json['offset'])

            if 'blocks' in self.json:
                blocks = self.json['blocks']
                dict_block = {}

                # Create a dictionary of all blocks in this CFG
                for block in blocks:
                    if block['ops'][0]:
                        dict_block[block['offset']] = [Block(block['offset'], block['ops']), block]

                # Match up all the block objects to their corresponding jump, fail addresses
                for key, pair in dict_block.items():
                    block_obj = pair[0]
                    block_json = pair[1]

                    block_obj.fail = None
                    block_obj.jump = None

                    if 'fail' in block_json:
                        try:
                            block_obj.fail = dict_block[block_json['fail']][0]
                            block_obj.fail.parents.append(block_obj)
                        except KeyError:
                            continue
                    if 'jump' in block_json:
                        try:
                            block_obj.jump = dict_block[block_json['jump']][0]
                            block_obj.jump.parents.append(block_obj)
                        except KeyError:
                            continue

                self.blocks = dict_block
                self.first = dict_block[(int(self.base_addr, 16))][0]


class Function:
    def __init__(self, base_addr, cfg):
        """
        :param base_addr: Address of function
        :param cfg: CFG json pulled from radare2
        """
        self.base_addr = base_addr
        self.children = {}
        self.parents = {}
        self.cfg = cfg


class EcuFile:
    def __init__(self, filename, r2):
        self.filename = filename

        split = filename.split('/')
        name = split[len(split) - 1].split('-')
        self.name = name[0][4:] + '-' + name[1][2:] + '-' + name[4].split('.')[0]

        r2 = setup_r2("./bins/{}".format(filename))
        r2.cmd('aaa')

        self.rom_start = self.get_rom_start(r2)
        self.rvector_location = self.get_rvector_location(r2)
        self.fix_rvector(r2)

        self.get_functions(r2, self.rvector_location)
        print('count {}'.format(len(self.visited_fcns.items())))
        for address, fcn in sorted(self.visited_fcns.items()):
            print(address)

    def get_rom_start(self, r2):
        """
        Gets the address of code start
        """
        inst = str(r2.cmd('/c CMP al #0xf0'), 'ISO-8859-1')
        if inst is "":
            inst = str(r2.cmd('/c CMP ax #0xf0f0'), 'ISO-8859-1')

        return int(inst.split()[0], 16)

    def get_rvector_location(self, r2):
        """
        Get addr location of the reset vector
        :param r2: radare2 instance
        """
        r2.cmd('s 0xfffe')
        location = str(r2.cmd('px0'), 'ISO-8859-1')[:4]

        return "0x{}".format(location[2:4] + location[:2])

    def fix_rvector(self, r2):
        """
        Get all calls made in the reset vectors main loop
        :param r2: radare2 instance
        """
        r2.cmd('s 0x{}'.format(self.rvector_location))
        r2.cmd('aa')

        # Get 1000 instructions due to radare2 stopping too early with analysis
        # Fix was to use command 'afu' to resize function after finding main loop
        instructions = load_json(str(r2.cmd('pdj 1000'), 'ISO-8859-1'))
        calls = []
        stores = 0
        watch = False

        for i, ins in enumerate(instructions):
            if not ins:
                continue

            split = ins['opcode'].split(' ')

            if not watch:
                stores += 1 if split[0] == 'STA' else 0

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

    def get_functions(self, r2, fcn_address, visited_fcns=None):
        if visited_fcns is None:
            self.visited_fcns = OrderedDict()
        else:
            r2.cmd('s {}'.format(fcn_address))
            r2.cmd('aa; sf.')

        fcn_address = str(r2.cmd('s'), 'ISO-8859-1').strip()
        # print('looking at {}'.format(fcn_address))
        self.visited_fcns[fcn_address] = Function(fcn_address,
            Cfg(load_json(str(r2.cmd("agj"), 'ISO-8859-1')))
        )

        calls = r2.cmd('pdf~JSR')
        calls = str(calls, 'ISO-8859-1').split()

        for index, value in enumerate(calls):
            if value == 'JSR':
                jmp_address = "0x{}".format(calls[index + 1][-4:])

                if jmp_address not in self.visited_fcns:
                    self.get_functions(r2, jmp_address, self.visited_fcns)



def setup_r2(file_path):
    """
    radare2 helper for M7700 setup
    :param file_path: Full path of binary to load
    """
    r2 = r2pipe.open(file_path, ['-2'])
    r2.cmd('e asm.arch=m7700')
    r2.cmd('e anal.limits=true')
    r2.cmd('e anal.from=0x8000')
    r2.cmd('e anal.to=0xffd0')

    return r2

def load_json(json_str):
    result = None

    if json_str:
        json_str = json_str.replace("'", "\"").replace('\"\"', '0').replace("\"esil\": \"re\"", "\"re\"")
        try:
            result = json.loads(json_str, strict=False, object_pairs_hook=OrderedDict)
        except Exception as e:
            try:
                json_str = list(json_str)
                json_str[e.pos] = ''
                new_json = ''.join(json_str)
            except Exception as a:
                return []

            return load_json(new_json)

    return result

def analyze_bins():
    """
    Create EcuFile instances for bins in the directory
    """
    bins = {}

    for filename in os.listdir(BIN_DIR):
        bins[filename] = EcuFile(filename, setup_r2("{}/{}".format(BIN_DIR, filename)))
        print("Loaded {}".format(filename))

    return bins

if __name__ == '__main__':
    bins = analyze_bins()
