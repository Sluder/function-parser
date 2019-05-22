#!/usr/bin/python

import r2pipe
import os
import json
import md5
from collections import OrderedDict, Counter

# List control binaries for clustering
control_bins = {
    "722527-1993-USDM-SVX-EG33.bin" : None,
    "703243-1991-EDM-Legacy-EJ22.bin" : None,
    "74401A-1995-JDM-WrxRA-EJ20T.bin" : None
}

# List for clustered binaries
clusters = {}


class Instruction:
    def __init__(self, base_addr, instruction):
        self.base_addr = hex(base_addr)

        params = instruction.split()
        self.opcode = params[0]
        self.params = params[1:]

    def __str__(self):
        if self.params:
            return "Opcode: {}, Params: {}\n".format(self.opcode, self.params)
        return "Opcode: {}\n".format(self.opcode)


class Block:
    def __init__(self, base_addr, seq_json):
        self.base_addr = hex(base_addr)
        self.parents = []
        self.instructions = OrderedDict()

        for op in seq_json:
            self.instructions[op['offset']] = Instruction(op['offset'], op['opcode'])

    def get_instructions(self, should_hash=True):
        """
        String representation of block instructions
        :param should_hash: Return hask of opcodes or not
        """
        opcodes = ""

        for instruction in self.instructions.values():
            opcodes = opcodes + str(instruction.opcode)

        return md5.new(opcodes).hexdigest() if should_hash else opcodes

    def _n_grams(self, stop_addr=None, get_first_ops=True, n_grams=2):
        grams = []
        ret = []
        opcodes = []

        if stop_addr is None:
            for key in self.instructions.keys():
                opcodes.append(self.instructions[key].opcode)
        else:
            if get_first_ops:
                for key in self.instructions.keys():
                    if key == stop_addr:
                        break
                    opcodes.append(self.instructions[key].opcode)
            else:
                post_key = False

                for key in self.instructions.keys():
                    if key == stop_addr:
                        post_key = True
                    elif post_key:
                        opcodes.append(self.instructions[key].opcode)

        # Split list into N-gram opcodes if number of grams in list is sufficient
        if n_grams > 0 and n_grams < len(opcodes):
            grams = zip(*[opcodes[i:] for i in range(n_grams)])
        # Otherwise, check to see if list passes the minimum length requirement
        elif n_grams == 0 or n_grams >= len(opcodes):
            grams = ["".join(opcodes)]

        if grams is not None:
            for pair in grams:
                ret.append("".join(pair))

        return ret

    def gen_features(self, sensor, depth=1):
        features = {0:[], 1:[]}
        li = self.instructions
        found = False
        instruction_addr = 0

        for address, instruction in li.iteritems():
            if sensor[1] == instruction:
                found = True
                instruction_addr = address

        if found:
            features[0] = self._gen_preceeding_grams(instruction_addr)
            features[1] = self._gen_following_grams(instruction_addr)

        return features

    def _gen_preceeding_grams(self, instruction_addr, depth=1):
        ret = []
        parents_have_parents = False
        for parent in self.parents:
            ret.extend(parent._n_grams())
            if parent.parents is not None:
                parents_have_parents = True

        ret.extend(self._n_grams(instruction_addr))

        if depth > 0 and parents_have_parents:
            for parent in self.parents:
                if parent.parents is not None:
                    ret.extend(parent._gen_preceeding_grams(instruction_addr, depth - 1))

        return ret

    def _gen_following_grams(self, instruction_addr, depth=1):
        ret = []
        ret.extend(self._n_grams(instruction_addr, False))
        if self.fail is not None:
            ret.extend(self.fail._n_grams())
            if depth > 0:
                ret.extend(self.fail._gen_following_grams(instruction_addr, depth - 1))
        if self.jump is not None:
            ret.extend(self.jump._n_grams())
            if depth > 0:
                ret.extend(self.jump._gen_following_grams(instruction_addr, depth - 1))

        return ret

    def feature_gen_p2(self):
        features = {}
        n = 2
        li = self.instructions
        keys = li.keys()
        vals = li.values()

        for val in vals:
            feat = ""
            start = vals.index(val)
            sub_list = vals[start: start + n - 1]
            for instr in sub_list:
                feat = "{}{}".format(feat, instr.opcode)

            # append first instr of next blocks
            if self.fail is not None:
                feat = "{}{}".format(feat, self.fail.instructions.get(int(self.fail.base_addr, 16)).opcode)
            if self.jump is not None:
                feat = "{}{}".format(feat, self.jump.instructions.get(int(self.jump.base_addr, 16)).opcode)

            features[val.base_addr] = feat

        return features

    def __str__(self):
        ret = "Addr: 0x{:04x}\n".format(self.base_addr)

        if self.fail:
            ret += "\tFail: 0x{:04x}\n".format(self.fail.base_addr)
        if self.jump:
            ret += "\tJump: 0x{:04x}\n".format(self.jump.base_addr)

        return ret

class Cfg:
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

    def gen_features(self, instr, blk):
        return blk.gen_features(instr)

    def get_ctrl_feature(self, blk, sensor):
        features = {}

        if blk is not None:
            il = blk.instructions
            feature_visited.append(blk)
            for instr in il.items():
                for param in instr[1].params:
                    if sensor.lower() in features.keys():
                        if sensor.lower() in param.lower():
                            features[ur"{}".format(param)].update(self.gen_features(instr, blk))
                    else:
                        if sensor.lower() in param.lower():
                            features[sensor] = self.gen_features(instr, blk)
            # recurse through all later blocks to look for additional candidates
            if (blk.jump is not None and blk.jump not in feature_visited):
                features.update(self.get_ctrl_feature(blk.jump, sensor))
            if (blk.fail is not None and blk.fail not in feature_visited):
                features.update(self.get_ctrl_feature(blk.fail, sensor))

        return features

    def get_feature(self, blk):
        features = {}
        global feature_visited

        #check item for LDA candidate, potential for sensor
        if blk is not None:
            il = blk.instructions
            feature_visited.append(blk)
            for instr in il.items():
                #if (((u'STA' in instr[1].opcode or u'STB' in instr[1].opcode or instr[1].opcode == u'LDA') or (instr[1].opcode == u'LDB')) and not ("al" in instr[1].params[0] or "bl" in instr[1].params[0]  or "ax" in instr[1].params[0] or "bx" in instr[1].params[0] or "xl" in instr[1].params[0] or "yl" in instr[1].params[0])):
                try:
                    for param in instr[1].params:

                        if param not in features.keys() and "0x" in param and "#" not in param and "$" not in param:
                            if int(param, 16) < 0x6000:
                                features[ur"{}".format(param)] = self.gen_features(instr, blk)
                        elif param in features.keys():
                            features[ur"{}".format(param)].update(self.gen_features(instr, blk))
                        elif "$" in param and "0x" in param:
                            hex_param = "{}".format(param[1:])  # remove $ from param
                            if int(hex_param, 16) < 0x6000:
                                if hex_param not in features.keys():
                                    features[ur"{}".format(hex_param)] = self.gen_features(instr, blk)
                                else:
                                    features[ur"{}".format(hex_param)].update(self.gen_features(instr, blk))

                except IndexError as ie:
                    print ie
                    continue
            # recurse through all later blocks to look for additional candidates
            if (blk.jump is not None and blk.jump not in feature_visited):
                features.update(self.get_feature(blk.jump))
            if (blk.fail is not None and blk.fail not in feature_visited):
                features.update(self.get_feature(blk.fail))

        return features

    def __str__(self):
        ret = ""
        node = self.first

        while node is not None:
            ret += "{}\n".format(node)

            if node.fail:
                node = node.fail
            else:
                node = node.jump

        return ret


class Function:
    base_addr = 0x0
    json = ""
    dot = ""

    def __init__(self, base_addr, cfg):
        self.base_addr = base_addr
        self.children = {}
        self.parents = {}
        self.cfg = cfg

    def get_features(self):
        global feature_visited
        feature_visited = list()

        return self.cfg.get_feature(self.cfg.first)

    def get_ctrl_features(self, sensor):
        global feature_visited
        feature_visited = list()

        return self.cfg.get_ctrl_feature(self.cfg.first, sensor)

    def __str__(self):
        ret = "{}\n".format(self.base_addr)

        for child in self.children.values():
            ret += "\t{}".format(child)

        return ret


class EcuFile:
    def __init__(self, filename, r2):
        self.filename = filename

        split = filename.split('/')
        name = split[len(split) - 1].split('-')
        self.name = name[0][4:] + '-' + name[1][2:] + '-' + name[4].split('.')[0]

        r2.cmd('e asm.arch=m7700')
        r2.cmd('e anal.limits=true')
        r2.cmd('e anal.from=0x8000')
        r2.cmd('e anal.to=0xffd0')

        self.get_rvector_location(r2)
        self.get_rvector_calls(r2)
        self.analyze_rvector(r2)

        self.analyze_healthcheck(r2)

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

        # Get 1000 instructions due to radare2 stopping too early with analysis
        # Fix was to use 'afu' to resize function after finding main loop
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

    def analyze_rvector(self, r2):
        """
        Grab reset vector blocks
        """
        self.rvector_cfg = Cfg(json.loads(
            unicode(r2.cmd("agj"), errors='ignore'), strict=False, object_pairs_hook=OrderedDict
        ))
        hashes = []
        for offset, pair in self.rvector_cfg.blocks.items():
            hashes.append(pair[0].get_instructions())
        self.rvector_hashes = hashes

    def analyze_healthcheck(self, r2):
        """
        Grab healthcheck blocks
        """
        healthcheck = Counter(self.rvector_jmps).most_common(1)
        self.healthcheck = healthcheck[0][0] if healthcheck else "?"

        r2.cmd("s 0x{}".format(self.healthcheck))
        r2.cmd("aa")
        self.healthcheck_cfg = Cfg(json.loads(
            unicode(r2.cmd("agj"), errors='ignore'), strict=False, object_pairs_hook=OrderedDict
        ))

        instructions = []
        for offset, pair in self.healthcheck_cfg.blocks.items():
            instructions.append(pair[0].get_instructions())
        self.healthcheck_hashes = instructions

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

def setup_controls():
    """
    Setup & parse control binaries
    """
    for filename, _ in control_bins.items():
        r2 = r2pipe.open('./bins/{}'.format(filename))
        control_bins[filename] = EcuFile(filename, r2)
        clusters[filename] = []

        print("Created control for {}".format(filename))

def cluster_bins():
    """
    Cluster unknown binaries based on the controls
    """
    for filename_1 in os.listdir('./bins'):
        r2 = r2pipe.open('./bins/' + filename_1)
        ecu = EcuFile(filename_1, r2)

        highest_value = 0
        highest_control = None

        for filename_2, control in control_bins.items():
            value = jaccard_index(ecu.rvector_hashes, control.rvector_hashes)

            if value > highest_value:
                highest_value = value
                highest_control = filename_2

        clusters[highest_control].append(filename_1)

        print("Parsed {}".format(filename_1))

def print_clusters():
    """
    Output clustering results
    """
    for control, bins in clusters.items():
        print(control)

        for bin in bins:
            print("\t{}".format(bin))

if __name__ == '__main__':
    setup_controls()
    cluster_bins()

    with open('clusters.json', 'w') as file:
        json.dump(clusters, file)
