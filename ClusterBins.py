#!/usr/bin/python

import r2pipe
import os
import json
import numpy
import pandas
import operator
import hashlib
import argparse
from collections import OrderedDict, Counter
from sklearn.cluster import AgglomerativeClustering
from itertools import count

BIN_DIR = './bins'

class Instruction:
    def __init__(self, base_addr, instruction):
        self.base_addr = hex(base_addr)

        operands = instruction.split()
        self.opcode = operands[0]
        self.operands = operands[1:]

    def __str__(self):
        if self.operands:
            return "Opcode: {}, Operands: {}\n".format(self.opcode, self.operands)
        return "Opcode: {}\n".format(self.opcode)


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

    def n_grams(self, stop_addr=None):
        """
        Creates list of opcodes for this blocks instructions
        :param stop_addr: Address to stop grabbing opcodes
        """
        opcodes = []

        for address, instruction in self.instructions.items():
            if stop_addr is not None and address == stop_addr:
                break
            opcodes.append(instruction.opcode)

        return opcodes

    def gen_features(self, inst, depth=1):
        """
        :param inst: Instruction instance to get features for
        :param depth: Number of blocks to get features from before/after inst
        """
        features = {"pre":[], 'post':[]}
        found = False
        instruction_addr = None

        for address, instruction in self.instructions.items():
            if inst.base_addr == instruction.base_addr:
                found = True
                instruction_addr = address

        if found:
            features["pre"] = self._gen_preceeding_grams(instruction_addr)
            features["post"] = self._gen_following_grams(instruction_addr)

        return features

    def _gen_preceeding_grams(self, instruction_addr, depth=1):
        """
        :param instruction_addr: Base address of instruction
        :param depth: Number of blocks to get features from before/after inst
        """
        ret = []
        has_parent = False

        for parent in self.parents:
            ret.extend(parent.n_grams())

            if parent.parents is not None:
                has_parent = True

        ret.extend(self.n_grams(instruction_addr))

        if depth > 0 and has_parent:
            for parent in self.parents:
                if parent.parents is not None:
                    ret.extend(parent._gen_preceeding_grams(instruction_addr, depth - 1))

        return ret

    def _gen_following_grams(self, instruction_addr, depth=1):
        """
        :param instruction_addr: Base address of instruction
        :param depth: Number of blocks to get features from before/after inst
        """
        ret = []
        ret.extend(self.n_grams(instruction_addr))

        if self.fail is not None:
            ret.extend(self.fail.n_grams())

            if depth > 0:
                ret.extend(self.fail._gen_following_grams(instruction_addr, depth - 1))
        if self.jump is not None:
            ret.extend(self.jump.n_grams())

            if depth > 0:
                ret.extend(self.jump._gen_following_grams(instruction_addr, depth - 1))

        return ret

    def __str__(self):
        ret = "Addr: 0x{}\n".format(self.base_addr)

        if self.fail:
            ret += "\tFail: 0x{}\n".format(self.fail.base_addr)
        if self.jump:
            ret += "\tJump: 0x{}\n".format(self.jump.base_addr)

        return ret

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

    def get_control_features(self, block, sensor_addr, visited_blocks=None):
        """
        Gets features for a specific address
        :param block: Current block we are looking at
        :param sensor_addr: Address to gather features for
        :param visited_blocks: List of already visited blocks
        """
        features = {}
        sensor_addr = sensor_addr.lower()

        # Reset visited blocks
        if visited_blocks == None:
            visited_blocks = []

        if block is not None:
            instructions = block.instructions
            visited_blocks.append(block)

            for address, inst in instructions.items():
                for operand in inst.operands:
                    operand = operand.lower()

                    if sensor_addr in operand:
                        if sensor_addr in features.keys():
                            if sensor_addr in operand:
                                features[operand].update(block.gen_features(inst))
                        elif sensor_addr in operand:
                            features[sensor_addr] = block.gen_features(inst)

            # Jump to connected blocks
            if block.jump is not None and block.jump not in visited_blocks:
                features.update(self.get_control_features(block.jump, sensor_addr, visited_blocks))
            if block.fail is not None and block.fail not in visited_blocks:
                features.update(self.get_control_features(block.fail, sensor_addr, visited_blocks))

        return features

    def get_features(self, block, visited_blocks=None):
        """
        :param block: Current block to get feature for (Start with self.first)
        :param sensor_addr: Sensor address to filter features for
        """
        features = {}

        # Reset visited blocks on first call
        if visited_blocks == None:
            visited_blocks = []

        if block is not None:
            instructions = block.instructions
            visited_blocks.append(block)

            for address, inst in instructions.items():
                for operand in inst.operands:
                    # If operand is an address, could be a sensor address
                    if operand not in features.keys() and operand.startswith("0x"):
                        if int(operand, 16) >= 0x1000 and int(operand, 16) <= 0x14ff:
                            features[str(operand)] = block.gen_features(inst)

                    elif operand in features.keys():
                        features[str(operand)].update(block.gen_features(inst))

                    elif operand.startswith("$0x"):
                        hex = operand[1:]
                        if int(hex, 16) >= 0x1000 and int(hex, 16) <= 0x14ff:
                            if hex not in features.keys():
                                features[str(hex)] = block.gen_features(inst)
                            else:
                                features[str(hex)].update(block.gen_features(inst))

            # Recurse through connected blocks for features
            if block.jump is not None and block.jump not in visited_blocks:
                features.update(self.get_features(block.jump, visited_blocks))
            if block.fail is not None and block.fail not in visited_blocks:
                features.update(self.get_features(block.fail, visited_blocks))

        return features

    def get_hashes(self, current_block, visited_blocks=None):
        """
        :param current_block: Current block to build hashes for
        :param vistited_list: List of Block instances already visited
        """
        hashes = []

        if current_block == None:
            return []

        # Reset visited blocks on first call
        if visited_blocks == None:
            visited_blocks = []

        hashes.append(current_block.get_opcodes())
        visited_blocks.append(current_block)

        if current_block.jump is not None and current_block.jump not in visited_blocks:
            hashes.extend(self.get_hashes(current_block.jump, visited_blocks))
        if current_block.fail is not None and current_block.fail not in visited_blocks:
            hashes.extend(self.get_hashes(current_block.fail, visited_blocks))

        return hashes

    def __str__(self):
        ret = ""
        node = self.first

        while node is not None:
            ret += "{}\n".format(node)
            node = node.fail if node.fail else node.jump

        return ret


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

    def get_ctrl_features(self, sensor_addr):
        """
        Gets all features for a sensor
        :param sensor_addr: Sensor address to filter features for
        """
        if not self.cfg.first:
            return {}
        return self.cfg.get_control_features(self.cfg.first, sensor_addr)

    def get_features(self):
        """
        Gets all features for sensor address candidates
        """
        if not self.cfg.first:
            return {}
        return self.cfg.get_features(self.cfg.first)

class EcuFile:
    def __init__(self, filename, r2, sensor_functions=None):
        self.filename = filename

        split = filename.split('/')
        name = split[len(split) - 1].split('-')
        self.name = name[0][4:] + '-' + name[1][2:] + '-' + name[4].split('.')[0]

        r2 = setup_r2("./bins/{}".format(filename))

        self.get_rom_start(r2)
        self.get_rvector_location(r2)
        self.get_rvector_calls(r2)
        self.analyze_rvector(r2)
        # self.analyze_healthcheck(r2)

        # Only called if this bin is the control for a cluster
        if sensor_functions:
            self.load_sensors(r2, sensor_functions)

    def get_rom_start(self, r2):
        """
        Gets the address of code start
        """
        inst = str(r2.cmd('/c CMP al #0xf0'), 'ISO-8859-1')
        if inst is "":
            inst = str(r2.cmd('/c CMP ax #0xf0f0'), 'ISO-8859-1')

        self.rom_start = int(inst.split()[0], 16)

    def get_rvector_location(self, r2):
        """
        Get addr location of the reset vector
        :param r2: radare2 instance
        """
        r2.cmd('s 0xfffe')
        location = str(r2.cmd('px0'), 'ISO-8859-1')[:4]

        self.rvector_location = location[2:4] + location[:2]

    def get_rvector_calls(self, r2):
        """
        Get all calls made in the reset vectors main loop
        :param r2: radare2 instance
        """
        r2.cmd('s 0x{}'.format(self.rvector_location))
        r2.cmd('aa')

        # Get 1000 instructions due to radare2 stopping too early with analysis
        # Fix was to use command 'afu' to resize function after finding main loop
        instructions = json.loads(
            str(r2.cmd('pdj 1000'), 'ISO-8859-1'), strict=False, object_pairs_hook=OrderedDict
        )
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

        self.rvector_jmps = calls

    def analyze_rvector(self, r2):
        """
        Grab reset vector blocks
        :param r2: radare2 instance
        """
        self.rvector_cfg = Cfg(json.loads(
            str(r2.cmd("agj"), 'ISO-8859-1'), strict=False, object_pairs_hook=OrderedDict
        ))
        hashes = []
        for offset, pair in self.rvector_cfg.blocks.items():
            hashes.append(pair[0].get_opcodes())
        self.rvector_hashes = hashes

    def analyze_healthcheck(self, r2):
        """
        Grab healthcheck blocks
        :param r2: radare2 instance
        """
        healthcheck = Counter(self.rvector_jmps).most_common(1)
        if not healthcheck:
            self.healthcheck = "0x0000"
            return
        self.healthcheck = healthcheck[0][0]

        r2.cmd("s 0x{}".format(self.healthcheck))
        r2.cmd("aa")
        self.healthcheck_cfg = Cfg(json.loads(
            str(r2.cmd("agj"), 'ISO-8859-1'), strict=False, object_pairs_hook=OrderedDict
        ))

        instructions = []
        for offset, pair in self.healthcheck_cfg.blocks.items():
            instructions.append(pair[0].get_opcodes())
        self.healthcheck_hashes = instructions

    def load_sensors(self, r2, sensor_list):
        """
        Only used for control bins
        :param r2: radare2 instance
        :param sensor_list: List of sensors & addresses from control json
        """
        self.sensors = {}

        for sensor, functions in sensor_list.items():
            self.sensors[sensor] = []

            for function in functions:
                r2.cmd("s {}".format(function))
                r2.cmd("aa")
                self.sensors[sensor].append(Function(function, Cfg(json.loads(
                    str(r2.cmd("agj"), 'ISO-8859-1'), strict=False, object_pairs_hook=OrderedDict
                ))))


class Cluster:
    _id = count(1)

    def __init__(self, bins):
        """
        :param bins: List of all bins assigned to this cluster
        """
        self.bins = bins
        self.id = next(self._id)

    def match_functions(self, bins):
        """
        Matches bin functions with ones identified for sensors
        :param bins: List of all bins. Used for gathering feature hashes
        """
        matches = {}

        for bin in self.bins:
            print("Matching functions for {}".format(bin.filename))
            matches[bin.filename] = []

            r2 = setup_r2("{}/{}".format(BIN_DIR, bin.filename))

            for sensor, sensor_fcns in self.control.sensors.items():
                for sensor_fcn in sensor_fcns:
                    control_bin = bins[self.control.filename]
                    sensor_fcn.sensor = sensor

                    # Get hashes of CFG if the functions file didnt have it
                    if sensor_fcn.base_addr in control_bin.functions.keys():
                        control_hashes = control_bin.functions[sensor_fcn.base_addr].hashes
                    else:
                        r2.cmd("s {}".format(sensor_fcn.base_addr))
                        r2.cmd('aa')

                        cfg = Cfg(json.loads(
                            str(r2.cmd("agj"), 'ISO-8859-1'), strict=False, object_pairs_hook=OrderedDict
                        ))
                        control_hashes = cfg.get_hashes(cfg.first)

                    highest_jaccard = 0
                    chosen_fcn = None

                    # Test all functions against the control function
                    for test_fcn in bin.functions.values():
                        value = jaccard_index(control_hashes, test_fcn.hashes)

                        if value > highest_jaccard:
                            highest_jaccard = value
                            chosen_fcn = test_fcn
                    matches[bin.filename].append({sensor_fcn: chosen_fcn})
                    # print('{} {} - {}', bin.filename, sensor_fcn.base_addr, chosen_fcn.base_addr)
            r2.quit()

        self.fcn_matches = matches

        return matches

    def match_sensors(self, should_simplify):
        """
        Find corresponding sensor addresses using the matched functions
        :param should_simplify: Whether results should only show found sensors
        """
        matches = {}

        # Matching results setup (Doing this below clears some results)
        for filename in self.fcn_matches.keys():
            matches[filename] = {}

            for sensor in self.control.sensors.keys():
                matches[filename][sensor] = {}

        # Match up sensor addresses from matched functions
        for filename, fcn_matches in self.fcn_matches.items():
            print("Matching sensor addresses for {}".format(filename))

            for match in fcn_matches:
                for control_fcn, matched_fcn in match.items():
                    sensor_addr = self.sensors[control_fcn.sensor]

                    if matched_fcn == None:
                        continue

                    control_features = control_fcn.get_ctrl_features(sensor_addr)
                    match_features = matched_fcn.get_features()

                    for addr, addr_features in match_features.items():
                        # Average the 'pre' & 'post' features
                        try:
                            pre_jaccard = jaccard_index(
                                control_features[sensor_addr]['pre'], addr_features['pre']
                            )
                            post_jaccard = jaccard_index(
                                control_features[sensor_addr]['post'], addr_features['post']
                            )
                            average = (pre_jaccard + post_jaccard) / 2
                        except:
                            average = 0

                        matches[filename][control_fcn.sensor][addr] = round(average, 2)
        self.sensor_matches = matches

        if should_simplify:
            self.cleanup_sensor_matches()

    def cleanup_sensor_matches(self):
        """
        Helper to simplify sensor matches JSON
        """
        for filename, sensor_matches in self.sensor_matches.items():
            for sensor, matches in sensor_matches.items():
                if matches:
                    highest_addr = max(matches.items(), key=operator.itemgetter(1))[0]
                    self.sensor_matches[filename][sensor] = highest_addr

    def print_fcn_matches(self):
        """
        Helper to output function matches for all bins in this cluster
        """
        for filename, fcn_matches in self.fcn_matches.items():
            print(filename)

            for match in fcn_matches:
                for control_fcn, match_fcn in match.items():
                    print("\t{} - {}".format(control_fcn.base_addr, match_fcn.base_addr))

    def __str__(self):
        ret = "Cluster {}\n".format(self.id)

        for bin in self.bins:
            ret += "\t{}\n".format(bin.name)

        return ret

def jaccard_index(list_1, list_2):
    """
    Calculate Jaccard Index from two lists (Use shortest list as check)
    :param list_1, list_2: Lists to compare
    :returns: Jaccard index of list_1 & list_2
    """
    if list_1 == [] and list_2 == []:
        return 1.0

    if len(list_1) < len(list_2):
        intersection = len([x for x in list_1 if x in list_2])
    else:
        intersection = len([x for x in list_2 if x in list_1])

    union = len(list_1) + len(list_2) - intersection

    if union == 0:
        return 0
    return float(intersection / union)

def cluster_bins(bins):
    """
    Cluster binaries through Hierarchical Clustering
    :param bins: List of all bins to split into clusters
    :returns: Clustering list results
    """
    clusters = OrderedDict()
    matrix = numpy.empty((len(bins), len(bins)))

    # Create comparison matrix
    row = 0
    for ecu_1 in bins.values():
        col = 0

        for ecu_2 in bins.values():
            matrix[row][col] = jaccard_index(ecu_1.rvector_hashes, ecu_2.rvector_hashes)
            col += 1
        row += 1

    # Hierarchical Clustering
    ac_clusters = AgglomerativeClustering(
        n_clusters=None, compute_full_tree=True, distance_threshold=0.8, linkage='single'
    ).fit(matrix).labels_

    # Split bins into found clusters
    for i in range(len(ac_clusters)):
        if ac_clusters[i] not in clusters:
            clusters[ac_clusters[i]] = []
        index = list(bins.keys())[i]
        clusters[ac_clusters[i]].append(bins[index])

    return clusters

def setup_r2(file_path):
    """
    radare2 helper for M7700 setup
    :param file_path: Full path of binary to load
    """
    r2 = r2pipe.open(file_path)
    r2.cmd('e asm.arch=m7700')
    r2.cmd('e anal.limits=true')
    r2.cmd('e anal.from=0x8000')
    r2.cmd('e anal.to=0xffd0')

    return r2

def analyze_bins():
    """
    Create EcuFile instances for bins in the directory
    """
    bins = {}

    for filename in os.listdir(BIN_DIR):
        bins[filename] = EcuFile(filename, setup_r2("{}/{}".format(BIN_DIR, filename)))
        print("Loaded {}".format(filename))

    return bins

def build_clusters(bins):
    """
    Builds Cluster instances from grouped binaries
    :param bins: List of EcuFile instances
    """
    clusters = []

    for num, clustered_bins in cluster_bins(bins).items():
        if len(clustered_bins) >= 3:
            cluster = Cluster(clustered_bins)
            clusters.append(cluster)
            print(cluster)

    return clusters

def set_cluster_controls(clusters):
    """
    Load & setup control manual analysis
    :param clusters: List of Cluster instances
    """
    with open("controls.json") as file:
        controls_js = json.load(file)

        for control_filename, params in controls_js.items():
            split = control_filename.split('-')
            engine = split[len(split) - 1].split('.')[0]

            # Set control file for each cluster
            for cluster in clusters:
                if any(x for x in cluster.bins if engine in x.name):
                    cluster.sensors = params["sensors"]
                    cluster.control = EcuFile(
                        control_filename, setup_r2("{}/{}".format(BIN_DIR, control_filename)), params["sensor_functions"]
                    )
                    print("Set {} as control for Cluster {}".format(cluster.control.name, cluster.id))

def analyze_functions(bins):
    """
    Loads all function hashes and sets to corresponding EcuFile
    :param bins: List of EcuFile bins {filename: EcuFile instance}
    """
    with open("functions.json") as file:
        functions_js = json.load(file)

        # Analyze all bin files
        for filename, function_list in functions_js.items():
            if filename not in bins:
                continue
            bins[filename].functions = {}

            r2 = setup_r2("{}/{}".format(BIN_DIR, filename))

            # Analyze all functions for each file
            for function, hashes in function_list.items():
                if hashes == "[]":
                    continue

                r2.cmd("s {}".format(function))
                r2.cmd('aa')

                fcn = Function(function, Cfg(json.loads(
                    str(r2.cmd("agj"), 'ISO-8859-1'), strict=False, object_pairs_hook=OrderedDict
                )))

                hashes = hashes[1:-1].split(',')
                hashes = [x.replace('\'', '') for x in hashes]
                hashes = [x.strip(' ') for x in hashes]
                fcn.hashes = hashes

                bins[filename].functions[function] = fcn
            r2.quit()
            print("Loaded functions for {}".format(filename))

def write_clusters(clusters):
    """
    Output formatted clustering & sensor results
    :param clusters: List of Cluster instances
    """
    with open("cluster_matches.json", "w") as outfile:
        results = {}

        for cluster in clusters:
            results["Cluster {}".format(cluster.id)] = cluster.sensor_matches

        json.dump(results, outfile, indent=4)
        print("Write results to cluster_matches.json")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cluster M7700 binaries & find sensor addresses')
    parser.add_argument('-s', action='store_true', help='simplify sensor findings output')
    args = parser.parse_args()

    bins = analyze_bins()

    clusters = build_clusters(bins)
    set_cluster_controls(clusters)
    analyze_functions(bins)

    for cluster in clusters:
        cluster.match_functions(bins)
        cluster.match_sensors(args.s)

    write_clusters(clusters)
