#!/usr/bin/python

import sys
import json
import xlsxwriter
import r2pipe

# Predefined functions containing sensor addresses for comparision's
sensors = {
    "batt_voltage": ["0x9a50", "0xa20b", "0xa000", "0xa0f0", "0xabfe", "0xd809", "0xddf8"],
    "vehicle_speed": ["0x9c10", "0x9f13", "0xa1b7", "0xa633", "0xad12", "0xb500", "0xb91b"],
    "engine_speed": ["0x9cbe", "0xa31a", "0xa633", "0xadf3", "0xb4c2", "0xb87e", "0xc0d1"],
    "water_temp": ["0x9b7c", "0xa90b"],
    "ignition_timing": ["0xf91b", "0xf93f"],
    "airflow": ["0xdb5b"],
    "throttle_position": ["0xdd53"],
    "knock_correction": ["0xb2f3"]
}


class EcuFile:
    def __init__(self, file_name, functions):
        """
        EcuFile constructor
        :param file_name: File name of ECU binary
        :param functions: JSON of function address & block hashes
        """
        self.functions = {}

        split = file_name.split('/')
        name = split[len(split) - 1].split('-')
        self.name = name[0][4:] + '-' + name[1][2:] + '-' + name[4].split('.')[0]

        for address, hashes in functions.items():
            # Clean up hashes
            hashes = hashes[1:-1].split(',')
            hashes = [x.replace('\'', '') for x in hashes]
            hashes = [x.strip(' ') for x in hashes]

            self.functions[address] = hashes


class IndexTable:
    def __init__(self, ecu_file_1, ecu_file_2):
        """
        IndexTable constructor
        :param ecu_file_1, ecu_file_2: ECU files used for this table
        """
        self.indexes = {}
        self.name = ecu_file_1.name + ' ' + ecu_file_2.name

        print('Created index table ' + self.name)

    def push_index(self, function_1, function_2, jaccard_index):
        """
        Adds new 'cell' for table
        :param function_1, function_2: Header addresses
        :param jaccard_index: Jaccard Index calculation
        """
        self.indexes[function_1, function_2] = jaccard_index


def _jaccard_index(list_1, list_2):
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


def _create_tables(control_file, ecu_files):
    """
    Creates comparison tables
    :param ecu_files: List of EcuFile objects
    :returns: List of created tables
    """
    tables = []

    for ecu_file in ecu_files[1:]:
        table = IndexTable(control_file, ecu_file)

        # Loop through functions in ecu files
        for function_1, function_1_hashes in control_file.functions.items():
            for function_2, function_2_hashes in ecu_file.functions.items():
                for sensor, addresses in sensors.items():
                    if function_1 in addresses:
                        table.push_index(function_1 + ' - ' + sensor, function_2, _jaccard_index(function_1_hashes, function_2_hashes))
                        break

        tables.append(table)

    return tables


if __name__ == '__main__':
    ecu_files = []
    control_file = None

    if len(sys.argv) != 3:
        print('Run \'python JsonParser.py file.json output.xlsx')
        exit()

    # Open & parse JSON dump
    with open(sys.argv[1]) as file:
        json_data = json.load(file)

        for file_name in json_data:
            ecu_file = EcuFile(file_name, json_data[file_name])

            # Pick out control file
            if ecu_file.name == '14-95-EJ20T':
                control_file = ecu_file
            else:
                ecu_files.append(ecu_file)

    print('Loaded JSON data')

    tables = _create_tables(control_file, ecu_files)

    # Excel setup
    book = xlsxwriter.Workbook(sys.argv[2])

    header_format = book.add_format({'font_color': 'white', 'bg_color': 'black'})
    purple_format = book.add_format({'font_color': 'white', 'bg_color': 'purple'})
    blue_format = book.add_format({'font_color': 'white', 'bg_color': 'blue'})
    red_format = book.add_format({'font_color': 'white', 'bg_color': 'red'})

    # Write tables to Excel sheet
    for table in tables:
        print('Added & loading sheet ' + table.name)

        sheet = book.add_worksheet(table.name)
        sheet.freeze_panes(0, 1)
        sheet.set_column(0, 0, 23)

        row, col = 0, 0
        highest_index = [0, 0, 0]
        tmp_key = ''

        for keys, jaccard_index in table.indexes.items():
            if keys[0] != tmp_key:
                tmp_key = keys[0]
                row = row + 1
                col = 1

                # Highlights highest index in row
                if highest_index != [0, 0, 0]:
                    sheet.conditional_format(
                        highest_index[0], highest_index[1], highest_index[0], highest_index[1],
                        {'type': 'no_errors', 'format': purple_format}
                    )

                    highest_index = [0, 0, 0]
            else:
                col = col + 1

            # Check if encountered higher Jaccard index
            if jaccard_index > highest_index[2]:
                highest_index = [row, col, jaccard_index]

            sheet.write(0, col, keys[1], header_format)
            sheet.write(row, 0, keys[0], header_format)
            sheet.write(row, col, round(jaccard_index, 2), purple_format if jaccard_index == 1 else None)

        # Fix highlighting last row
        sheet.conditional_format(
            highest_index[0], highest_index[1], highest_index[0], highest_index[1],
            {'type': 'no_errors', 'format': purple_format}
        )

    book.close()

    print('\nWrote values to ' + sys.argv[2])
