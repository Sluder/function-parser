#!/usr/bin/python

import json
from pprint import pprint

class EcuFile:
    def __init__(self, file_name, functions):
        """
        EcuFile constructor
        """
        self.file_name = file_name.split('/')[2]
        self.functions = {}

        for address, hashes in functions.items():
            hashes = hashes[1:-1]

            self.functions[address] = hashes.split(',')

class IndexTable:
    def __init__(self):
        """
        IndexTable constructor
        """
        self.indexes = {}

    def push_index(self, function_1, function_2, jaccard_index):
        """
        Adds new 'cell' for table
        """
        self.indexes[function_1, function_2] = jaccard_index

def _jaccard_index(list_1, list_2):
    """
    Calculate Jaccard Index from two lists
    """
    intersection = len(list(set(list_1).intersection(list_2)))
    union = len(list_1) + len(list_2) - intersection

    return float(intersection) / union

if __name__ == '__main__':
    """
    Start of program
    """
    ecu_files = []

    with open('file.json') as file:
        json_data = json.load(file)

        for file_name in json_data:
            ecu_files.append(EcuFile(file_name, json_data[file_name]))

    # Create table
    index = 0

    for ecu_file in ecu_files:
        table = IndexTable()
