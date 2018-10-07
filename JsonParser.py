#!/usr/bin/python

import json
import xlsxwriter


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
        self.name = name[0][4:] + '-' + name[1][2:] + '-' + name[4].split('.')[0]

        for address, hashes in functions.items():
            self.functions[address] = hashes[1:-1].split(',')


class IndexTable:
    def __init__(self, ecu_file_1, ecu_file_2):
        """
        IndexTable constructor
        """
        self.indexes = {}
        self.name = ecu_file_1.name + ' ' + ecu_file_2.name

        print('Created table ' + table.name)

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

    with open('file.json') as file:
        json_data = json.load(file)

        for file_name in json_data:
            ecu_files.append(EcuFile(file_name, json_data[file_name]))

    print('Loaded JSON data')

    tables = _create_tables(ecu_files)

    # Write to Excel sheet
    book = xlsxwriter.Workbook('Tables.xlsx')

    header_format = book.add_format({'font_color': 'white', 'bg_color': 'black'})
    green_format = book.add_format({'font_color': 'white', 'bg_color': 'green'})

    for table in tables:
        sheet = book.add_worksheet(table.name)
        row = 0
        col = 0
        tmp_key = ''

        print('Added sheet ' + table.name)

        for keys, jaccard_index in table.indexes.items():
            if keys[0] != tmp_key:
                tmp_key = keys[0]
                row = row + 1
                col = 1
            else:
                col = col + 1

            sheet.write(0, col, keys[1], header_format)
            sheet.write(row, 0, keys[0], header_format)
            sheet.write(row, col, round(jaccard_index, 2), green_format if jaccard_index == 1 else None)

    book.close()

    print('Wrote values to Tables.xlsx')
