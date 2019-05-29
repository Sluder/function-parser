#!/usr/bin/python
"""
    This branch of the pysensor module takes a list of found addresses for likely sensors
    and returns a list of the sensor values for each of those addresses
"""
import sys
import argparse
import json
import jsongraph
import pprint
import r2pipe
import os
import os.path
import logging
import re
import subprocess
import networkx as nx
import pygraphviz
import md5
import pprint
import collections
import itertools
from collections import OrderedDict, Counter
from networkx.drawing import nx_agraph
from subprocess import check_call
from datetime import datetime

# template for all function data types

visited = {}
last_visited = {}
functions = []
feature_visited = list()

# Predefined functions containing sensor addresses for comparisions from the USDM 93 EG33
sensors = {
    'batt_voltage': ['0x9a56', '0x9f5b', '0xa166', '0xa307', '0xae2c', '0xd982', '0xe1cd'],
    'vehicle_speed': ['0x9be8', '0x9dce', '0xa59d', '0xa9a7', '0xafc6', '0xb5fc', '0xb960'],
    'engine_speed': ['0xa59d', '0xa5ec', '0xa9a7', '0xafc6', '0xb5bf', '0xb960', '0xc356'],
    'water_temp': ['0x9b46', '0xab56'],
    'ignition_timing': ['0xdb1a', '0xda0f'],
    'airflow': ['0xddcd'],
    'throttle_position': ['0xe1cd'],
    'knock_correction': ['0xafc6']
}

sensor_values = {
    'batt_voltage': '0x102f',
    'vehicle_speed': '0x1071',
    'engine_speed': '0x106f',
    'water_temp': '0x1185',
    'ignition_timing': '0x10a2',
    'airflow': '0x1283',
    'throttle_position': '0x128c',
    'knock_correction': '0x12a7'
}

class instruction:

    def __init__(self, base_addr, opcode):
        self.base_addr = hex(base_addr)
        params = opcode.split()
        self.opcode = params[0]
        self.params = params[1:]

    def __str__(self):
        if self.params:
            ret = "OP: {}\nParams: {}\n".format(self.opcode, self.params)
        else:
            ret = "OP: {}\n".format(self.opcode)
        return ret

class block:
    _parents = None
    fail = None
    jump = None

    def __init__(self, base_addr, seq_json):
        self.base_addr = hex(base_addr)
        self.seq_inst = OrderedDict()
        self._parents = list()
        for op in seq_json:
            self.seq_inst[op[u'offset']] = instruction(
                op[u'offset'], op[u'opcode'])

    # returns a hash of the instructions
    def get_seq_inst(self):
        temp = ur""
        for instruction in self.seq_inst.values():
            temp = temp + ur"{}".format(instruction.opcode)
        #logging.debug("block addr: {}, temp: {}\n".format(self.base_addr, temp))
        return [(md5.new(temp).hexdigest())]

    def ret_instruct_list(self):
        temp = ur""
        for instruction in self.seq_inst.values():
            temp = temp + ur"{}".format(instruction.opcode)
        #logging.debug("block addr: {}, temp: {}\n".format(self.base_addr, temp))
        return [temp]

    def print_inst(self):
        for instruction in self.seq_inst.itervalues():
            print(instruction)

    def __str__(self):
        ret = "Base_addr: 0x{:04x}\n".format(self.base_addr)
        if self.fail:
            ret += "\tFail: 0x{:04x}\n".format(self.fail.base_addr)
        if self.jump:
            ret += "\tJump: 0x{:04x}\n".format(self.jump.base_addr)
        return ret

    # Creates a list of all instructions for this block
    # tokenized into n-gram blocks. Returns that list.
    # Filter ignores the BRA instructions, leaving them out of gram creation.
    # Default program gram length: 2
    # If the grams provided exceed the length for a list, only items matching that length will
    # be added to the index.
    def _n_grams(self, stop_addr=None, get_first_ops=True, n_grams=2):
        #filter_list = args.ignore
        #get_consts = True
        #n_grams = args.ngrams
        #min_len = args.min_grams
        grams = list()
        ret = list()
        opcodes = []

        if stop_addr is None:
            # generate a filtered list of opcodes given the provided filter
            for key in self.seq_inst.keys():
                opcodes.append(self.seq_inst[key].opcode)

        else:
            if get_first_ops:
                for key in self.seq_inst.keys():
                    if key == stop_addr:
                        break
                    else:#append al instructions before key
                        opcodes.append(self.seq_inst[key].opcode)
            else:
                post_key = False
                for key in self.seq_inst.keys():
                    if key == stop_addr:
                        post_key = True
                    elif post_key: #append all instructions after key
                        opcodes.append(self.seq_inst[key].opcode)


        # split list into N-gram opcodes if number of grams in list is sufficient
        if n_grams > 0 and n_grams < len(opcodes):
            grams = zip(*[opcodes[i:] for i in range(n_grams)])
        # otherwise, check to see if list passes the minimum length requirement
        elif n_grams == 0 or n_grams >= len(opcodes):
            grams = ["".join(opcodes)] # just sub the whole list

        if grams is not None:
            for pair in grams:
                ret.append("".join(pair))

        return ret

    # Simple feature generation algorithm for blocks
    # generates features for a provided sensor instruction
    # First - locate a memory address that is being written to (sensor value)
    # can be a constant value loaded into a register, or a memory reference
    # TODO: Analyze semantic meaning of values loaded in functions to generate further features
    # Once you've located that memory value, create two features
    # first is all preceeding instructions, going back one block, split into two-gram pieces
    # second is all following instructions, going forward one block, split into two-gram pieces
    # the specific instruction that utilizes that opcode is not included in either feature
    # if there are no preceeding or following blocks, then it just continues to the end of the current block
    def gen_features(self, sensor, depth=1):
        features = {0:[], 1:[]}
        li = self.seq_inst # pull up list of instructions
        found = False
        instruction_addr = 0
       #for instr in li.items():  # first, search for the sensor
        for address, instruction in li.iteritems():
            if sensor[1] == instruction:
                found = True
                instruction_addr = address

        if found:
            features[0] = self._gen_preceeding_grams(instruction_addr)
            features[1] = self._gen_following_grams(instruction_addr)
            #features.update(self.feature_gen_p2())

        return features

    def _gen_preceeding_grams(self, instruction_addr, depth=1):
        ret = []
        parents_have_parents = False
        for parent in self._parents:
            ret.extend(parent._n_grams())
            if parent._parents is not None:
                parents_have_parents = True

        ret.extend(self._n_grams(instruction_addr))

        if depth > 0 and parents_have_parents:
            for parent in self._parents:
                if parent._parents is not None:
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
        li = self.seq_inst
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
                feat = "{}{}".format(feat, self.fail.seq_inst.get(int(self.fail.base_addr, 16)).opcode)
            if self.jump is not None:
                feat = "{}{}".format(feat, self.jump.seq_inst.get(int(self.jump.base_addr, 16)).opcode)

            features[val.base_addr] = feat

        return features

class CFG:
    first = None

    def __init__(self, json):
        if json:
            self.json = json[0]
        else:
            self.json = ""
        if u'offset' in self.json:
            self.base_addr = hex(json[0][u'offset'])
            if u'blocks' in json[0]:
                blocks = json[0][u'blocks']
                dict_block = {}
                # pass addr of first block, ops of first block, and pointers of first block

                #self.first = block(blocks[000][u'offset'], blocks[000][u'ops'])

                # create a dictionary of all blocks
                for blk in blocks:
                    dict_block [blk[u'offset']] = [block(
                    blk[u'offset'],
                    blk[u'ops']), blk]

                # match up all the block objects to their corresponding jump, fail addresses
                for _, pair in dict_block.items():
                    block_obj = pair[0]

                    block_json = pair[1]
                    # really, really sloppy method for now
                    # JSON has some weird errors where functions don't match up to the jump addresses
                    # might be an issue with the r2 debugger, but this is just a sloppy work-around
                    if u'fail' in block_json:
                        try:
                            block_obj.fail = dict_block[block_json[u'fail']][0]
                            block_obj.fail._parents.append(block_obj)

                        except KeyError:
                            continue

                    if u'jump' in block_json:
                        try:
                            block_obj.jump = dict_block[block_json[u'jump']][0]
                            block_obj.jump._parents.append(block_obj)

                        except KeyError:
                            continue

                self.first = dict_block[(int(self.base_addr, 16))][0]

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

    def print_blocks(self, start):
        ret = ""
        i = 0
        if start:
            for inst in start.seq_inst:
                ret = "{}{}".format(ret, inst)

            if start.jump is not None:
                ret = "{}{}".format(ret, self.print_blocks(start.jump))
            if start.fail is not None:
                ret = "{}{}".format(ret, self.print_blocks(start.fail))
        return ret

    def gen_features(self, instr, blk):

        features = blk.gen_features(instr)
        #features = blk.get_seq_inst()

        return features

    # targeted feature sensor creation, for use with known values
    def get_ctrl_feature(self, blk, sensor):
        features = {}

        if blk is not None:
            il = blk.seq_inst
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
    #returns list of features with address of sensors
    def get_feature(self, blk):
        features = {}
        global feature_visited

        #check item for LDA candidate, potential for sensor
        if blk is not None:
            il = blk.seq_inst
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

class function:
    base_addr = 0x0 # address of the function
    json = ""      # json representation of function pointed to
    dot = ""       # dot representation of function pointed to

    def __init__(self, base_addr, cfg):
        self.base_addr = base_addr
        self.children = {}
        self.parents = {}
        self.cfg = cfg

    def __str__(self):

        ret = "{}\n".format(self.base_addr)
        for child in self.children.values():
            ret += "\t{}".format(child)
        return ret

    def push_child(self, func):
        self.children[func.base_addr] = func

    def get_single_feature(self, addr):
        return self.cfg.get_feature()

    def get_features(self):
        global feature_visited
        feature_visited = list()
        return self.cfg.get_feature(self.cfg.first)

    def get_ctrl_features(self, sensor):
        global feature_visited
        feature_visited = list()
        return self.cfg.get_ctrl_feature(self.cfg.first, sensor)

# locates the reset vector address from a valid M7700 binary
# using a currently open radare2 session
def get_rst(r2):
    r2.cmd("s 0xfffe")     # seek to the address for the reset vector (const for all of our binaries)
    logging.debug("R2 Command used: 's 0xfffe'")

    big_endian = str(r2.cmd("px0")) # print last two bytes of rst vector
    logging.debug("R2 Command used: 'px0'")

    rst = 0x0

    if big_endian:
        rst = int("{}{}".format(big_endian[2:4], big_endian[:2]), 16) # flip endianness of last two bytes
        logging.debug("rst vector address found at: 0x{:04x}".format(rst))
    else:
        logging.debug("ERR - reset vector search failed")

    return rst

# Helper function for recursive_parse_func
# grabs all child function calls from a function analysis in R2
def get_children(child_str):
    p = ur"JSR.*[^$](0x[0-9a-fA-F]{4})" # grab unrecognized funcs
    children = re.findall(p, child_str)
    p1 = ur"JSR.*fcn.0000([0-9a-fA-F]{4})"
    ch2 = re.findall(p1, child_str)
    children.extend(ch2) # grab recognized funcs

    int_children = list()
    for child in children:
        try:
            int_children.append(int(child, 16))
        except TypeError:
            print (child)
    del children
    return int_children

# helper function for recursive parse func
# popluates
def populate_cfg(addr, func_json):

    #json_obj = json.loads('{}'.format(func_json.decode('utf-8', 'ignore').encode('utf-8')), strict=True, object_pairs_hook=collections.OrderedDict)
    json_obj=json.loads(unicode(func_json, errors='ignore'), strict=False, object_pairs_hook=collections.OrderedDict)
    cfg = CFG(json_obj)
    return cfg

def func_parse_str(func_str):
    ret = []
    fs = func_str.splitlines()
    for line in fs:
        try:
            addr = int(line[:10], 16)
        except TypeError:
            continue
        if addr and addr >= 36864:
            ret.append(addr)
    return ret
#fn = filename
def load_sensors(fn, sensor_list):
    ra2 = r2pipe.open(fn, ["-2"])

    if (ra2):
        sensor_obj = {}

        for sensor, sensor_addrs in sensor_list.iteritems():
            sensor_obj[sensor] = [] #OrderedDict() # declare a list at each sensor value

            #for sensor_type, sensor_addrs in sensor_list.iteritems(): # populate the list with the func disassembly
            for func_addr in sensor_addrs:
                ra2.cmd("s {}".format(func_addr))
                addr = ra2.cmd("s").strip()

                if "0x0" not in addr:
                    if addr not in visited.keys():
                        fcn_obj = function(addr, populate_cfg(addr, ra2.cmd("agj")))
                        sensor_obj[sensor].append(fcn_obj)
                    else:
                        sensor_obj[sensor].append(fcn_obj)

        ra2.quit()
    else:
        print "Radare couldn't open {}".format(fn)

    return sensor_obj

def get_sensor_val(val, control, test, all_control_features, args):

    sensor = "0x0000" # default value if not found
    control_sensor = sensor_values[val]

    sensor_feature = control.get_ctrl_features(control_sensor)[control_sensor]

    test_features = test.get_features()
    #sensor_feature = all_control_features[control_sensor]

    i = 0
    largest = 0
    largest_feature_vec = []

    for addr, feature in test_features.iteritems():

        j1, j2 = (jaccard(feature.values(), sensor_feature.values()))

        i = (j1 + j2) / 2

        if addr == control_sensor:
            addr_j1 = j1
            addr_j2 = j2

        if i > largest:
            largest = i
            sensor = addr
            largest_feature_vec = feature.values()
            largest_j1 = j1
            largest_j2 = j2
            # print sensor_feature.items()
            # print test_features.items()
        i = 0

    # try:
    #     actual = test_features[control_sensor]
    # except KeyError:
    #     print ""
    if args.long_output:
        ret = sensor
    else:
        ret = [sensor, {"jaccard": largest, "sensor_features": sensor_feature.values(), "candidate_features": largest_feature_vec}]

    ctrl_func_addr = control.base_addr
    test_func_addr = test.base_addr

    return ret

# helper method to quickly convert our file names into a more consise format
# this format is used in JSONParser as the names for the excel spreadsheets
def _json_parser_format(infile):
    split = infile.split('/')
    split = split[len(split) - 1]
    split = split.split('-')
    split = split[0][4:] + '-' + split[1][2:] + '-' + split[4].split('.')[0]
    return split

# specialized jaccard for averaging both of our lists
# returns jaccard of both sets
def jaccard(a, b):

    c = set(a[0]).intersection(set(b[0]))
    d = set(a[1]).intersection(set(b[1]))


    jacc1 = 0
    jacc2 = 0
    # if len(a[1]) == len(b[1]) == 0:
    #     jacc1 = 1
    # else: -- that condition doesn't appear
    jacc2 = (float(len(d) / float(len(set(a[1])) + len(set(b[1])) - len(d))))

    if len(a[0]) == len(b[0]) == 0:
        # specific condition accounting for null item sets matching in both
        # basically, if the sensor access is the first instruction,
        # no previous instructions will appear
        # this is a valid feature
        jacc1 = 1
    else:
        jacc1 = (float(len(c) / float(len(set(a[0])) + len(set(b[0])) - len(c))))

    #ret = (jacc1 + jacc2) / 2 # average the jaccard values

    return jacc1, jacc2
# Uses a given sensor function address and its matching candidate address
# to try and find the value of the sensor in the analyzed candidate
def find_sensors(control_func_addr, test_func_addr, args):
    func_sensors = {}

    for val in control_func_addr:
        z = OrderedDict(zip(control_func_addr[val], test_func_addr[val]))

        for control, test in z.iteritems():
            control_features = control.get_features()

            if func_sensors.has_key(val):
                func_sensors[val].append(get_sensor_val(val, control, test, control_features, args))
            else:
                func_sensors[val] = [get_sensor_val(val, control, test, control_features, args)]

    return func_sensors

def main ():
    # set up the parser first
    # default parser args - filename, opens file for JSON parsing
    # can also output JSON file as a .DOT file, or pull in a ROM and call R2
    file_dir = os.path.dirname(os.path.realpath(__file__))

    parser = argparse.ArgumentParser(description='Import and process M7700 JSON Graph files.')

    parser.add_argument('filename', metavar='filename', nargs='?', default='functions_test.json', type=str, help='M7700 ROM file for parsing')
    parser.add_argument('-s', '--settings', metavar='settings', default="controls_test.json", type=str, help='Specify Settings Filename')
    parser.add_argument('-l', '--long-output', metavar='long-output', default="ontrols_test.json", type=str, help='Extended JSON Output (contains feature vectors)')
    parser.add_argument('-o', '--output', action='store_true', help='Output M7700 rom to file')

    logging.basicConfig(filename='log_filename.txt', level=logging.DEBUG)

    args = parser.parse_args()
    with open(args.settings, 'r') as settings:
        print("Getting Control Configurations from file: {}".format(args.settings))
        control_files = json.load(settings)#"/home/greg/Documents/ROMs/EG33/USDM/722527-1993-USDM-SVX-EG33.bin"

    with open(args.filename, 'r') as json_file:
        #print("Opening file: {}".format(args.filename))
        # analyze the ROM's functions
        json_val = json.load(json_file)
        #func_list = json.loads(json_string)
        jsons = {}

    bins_dir = os.listdir("{}/bins/".format(os.getcwd()))
    file_list = {}
    for f in bins_dir:
        if (".bin") in f:
            file_list[_json_parser_format(f)] = f

    # control.json
    for control_file, control_params in control_files.iteritems():
        print(control_params)
        jsons = {}
        global sensor_values
        sensor_values = control_params['sensors']
        global sensors
        sensors = control_params['sensor_functions']
        #if "EG33" in control_file:
        engine = 'EJ20T'

        control_cfg = load_sensors("{}/bins/{}".format(os.getcwd(), control_file), control_params['sensor_functions'])

        # Lookup params from control file
        #functions.json
        for test_bin, files in json_val.iteritems(): # for file in the func list
            if engine in test_bin:
                print "Getting sensor features for Engine {}".format(engine)
                # for file & functions in all bins
                for fn, func_list in files.iteritems():
                    if fn not in u'Control':
                        jsons[fn] = None
                        sensor_list = load_sensors("{}/bins/{}".format(os.getcwd(), file_list[fn]), func_list)

                        # output format - each filename will have a list like the control list above
                        jsons[fn] = find_sensors(control_cfg, sensor_list, args)

                        for sensor, candidate_listings in jsons[fn].iteritems():
                            num_listings = dict(Counter(candidate_listings))
                            jsons[fn][sensor] = OrderedDict()

                            for sensor_val, num in num_listings.iteritems():
                                match_chance = float(float(num) / float(len(candidate_listings)))
                                if match_chance not in jsons[fn][sensor]:
                                    jsons[fn][sensor][match_chance] = [sensor_val]
                                else:
                                    jsons[fn][sensor][match_chance].append(sensor_val)


            with open('{}.json'.format(engine), 'w') as out:
                json.dump(jsons, out, indent=4, sort_keys=True)
                out.close()

# start
if __name__ == '__main__':
    main()
