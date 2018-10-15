#!/usr/bin/python

import json
import xlwt
from pprint import pprint

class EcuFile:
    def __init__(self, file_name, functions):
        """
        EcuFile constructor
        :param file_name: File name of ECU binary
        :param functions: JSON of function address & block hashes
        """
        self.file_name = file_name.split('/')[2]
        self.functions = {}

        name = self.file_name.split('-')
        self.name = name[1][2:] + '-' + name[4][:4]

        for address, hashes in functions.items():
            self.functions[address] = hashes[1:-1].split(',')

class IndexTable:
    def __init__(self, ecu_file_1, ecu_file_2):
        """
        IndexTable constructor
        """
        self.indexes = {}
        self.name = ecu_file_1.name + ' ' + ecu_file_2.name

    def push_index(self, function_1, function_2, jaccard_index):
        """
        Adds new 'cell' for table
        """
        self.indexes[function_1, function_2] = jaccard_index

def _jaccard_index(list_1, list_2):
    """
    Calculate Jaccard Index from two lists
    :param list_1, list2: Lists to compare
    :returns: Jaccard Index of list_1 & list_2
    """
    intersection = len(list(set(list_1).intersection(list_2)))
    union = len(list_1) + len(list_2) - intersection

    return float(intersection) / union

def _create_tables(ecu_files):
    """
    Creates comparison tables
    :param ecu_files: List of EcuFile objects
    :returns: List of created tables
    """
    tables = []

    # Loop through ecu files
    for key, ecu_file_1 in enumerate(ecu_files):
        for ecu_file_2 in ecu_files[(key + 1):]:
            table = IndexTable(ecu_file_1, ecu_file_2)

            # Loop through functions in ecu files
            for function_1, function_1_hashes in ecu_file_1.functions.items():
                for function_2, function_2_hashes in ecu_file_2.functions.items():
                    table.push_index(function_1, function_2, _jaccard_index(function_1_hashes, function_2_hashes))

            tables.append(table)

    return tables

if __name__ == '__main__':
    ecu_files = []

    with open('test.json') as file:
        json_data = json.load(file)

        for file_name in json_data:
            ecu_files.append(EcuFile(file_name, json_data[file_name]))

    tables = _create_tables(ecu_files)

    # Write to Excel sheet
    book = xlwt.Workbook()

    for table in tables:
        sheet = book.add_sheet(table.name)
        sheet.write(1, 0, 'test')

    book.save('Tables_test.xls')
