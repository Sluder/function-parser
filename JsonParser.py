#!/usr/bin/python

import sys
import json
import xlsxwriter
import r2pipe
from collections import OrderedDict

# Predefined functions containing sensor addresses for comparision's
sensors = {
    'batt_voltage': ['0x9a56', '0x9f5b', '0xa166', '0xa307', '-0xae2c', '0xd982', '0xe1cd'],
    'vehicle_speed': ['0x9be8', '0x9dce', '0xa59d', '0xa9a7', '0xafc6', '0xb960'],
    'engine_speed': ['0xa59d', '0xa5ec', '0xa9a7', '0xafc6', '0xb5bf', '0xb960'],
    'water_temp': ['0x9b46', '0xab56'],
    'ignition_timing': ['0xdb1a', '0xda0f'],
    'airflow': ['0xddcd'],
    'throttle_position': ['0xe1cd'],
    'knock_correction': ['0xafc6']
}
# How far left & right to show address range
hex_margin = 250

class EcuFile:
    def __init__(self, file_name, functions):
        """
        EcuFile constructor
        :param file_name: File name of ECU binary
        :param functions: JSON of function address & block hashes
        """
        self.functions = OrderedDict()

        split = file_name.split('/')
        self.file_name = split[len(split) - 1]
        name = self.file_name.split('-')
        self.name = name[0][4:] + '-' + name[1][2:] + '-' + name[4].split('.')[0]

        r2 = r2pipe.open('./bins/' + self.file_name)
        r2.cmd('e asm.arch=m7700')
        r2.cmd('e anal.limits=true')
        r2.cmd('e anal.from=0x9000')
        r2.cmd('e anal.to=0xffff')

        for address, hashes in functions.items():
            # Clean up hashes
            hashes = hashes[1:-1].split(',')
            hashes = [x.replace('\'', '') for x in hashes]
            hashes = [x.strip(' ') for x in hashes]

            if hashes != [''] and int(address, 16) > 36864:
                    self.functions[address] = hashes

        r2.quit()
        print('Created ECU file ' + self.file_name)


class IndexTable:
    def __init__(self, ecu_file_1, ecu_file_2):
        """
        IndexTable constructor
        :param ecu_file_1, ecu_file_2: ECU files used for this table
        """
        self.indexes = OrderedDict()
        self.tables = OrderedDict()
        self.name = ecu_file_1.name + ' ' + ecu_file_2.name
        self.test_name = ecu_file_2.file_name

        # Custom cell formats
        self.header_format = book.add_format({'font_color': 'white', 'bg_color': 'black'})
        self.purple_format = book.add_format({'font_color': 'white', 'bg_color': 'purple'})
        self.blue_format = book.add_format({'font_color': 'white', 'bg_color': 'blue'})
        self.yellow_format = book.add_format({'font_color': 'black', 'bg_color': 'yellow'})

        print('Created index table ' + self.name)

    def push_index(self, function_1, function_2, jaccard_index):
        """
        Adds new 'cell' for table
        :param function_1, function_2: Header addresses
        :param jaccard_index: Jaccard Index calculation
        """
        self.indexes[function_1, function_2] = jaccard_index

    def _write_format(self, sheet, highest_index):
        """
        Format cells with result data
        :param sheet: Excel sheet to write write results
        :param highest_index: Highest jaccad index in row
        """
        sheet.conditional_format(
            highest_index[0], highest_index[1], highest_index[0], highest_index[1],
            {'type': 'no_errors', 'format': self.blue_format}
        )

    def write_results(self, book):
        """
        Writes all results to Excel sheet
        :param book: Excel sheet containing result data
        :param test_blocks: Code blocks to test results with
        """
        print('Loading sheet ' + table.name)

        sheet = book.add_worksheet(table.name)
        sheet.freeze_panes(0, 1)
        sheet.set_column(0, 0, 23)

        row, col = 0, 0
        highest_index = [0, 0, 0]
        left_margin, right_margin = 0, 0
        tmp_key = ''

        # Write results to cells
        for keys, jaccard_index in table.indexes.items():
            # Switch to new row
            if keys[0] != tmp_key:
                tmp_key = keys[0]
                row = row + 1
                col = 1

                # Side header for each row
                sheet.write(row, 0, keys[0], self.header_format)
                print('\t Added row {}'.format(keys[0]))

                if highest_index != [0, 0, 0]:
                    self._write_format(sheet, highest_index)

                highest_index = [0, 0, 0]

                # Set address range margins
                hex_addr = int(keys[0].split(' ')[0], 16)
                left_margin = hex_addr - hex_margin
                right_margin = hex_addr + hex_margin
            else:
                col = col + 1

            # Check if encountered higher Jaccard index
            if jaccard_index > highest_index[2]:
                highest_index = [row, col, jaccard_index]

            # Highlight address margins
            if int(keys[1], 16) >= left_margin and int(keys[1], 16) <= right_margin:
                sheet.write(row, col, round(jaccard_index, 2), self.yellow_format)
            else:
                sheet.write(row, col, round(jaccard_index, 2))

            sheet.write(0, col, keys[1], self.header_format)

        self._write_format(sheet, highest_index)


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

    for ecu_file in ecu_files:
        table = IndexTable(control_file, ecu_file)

        # Loop through functions in ECU files
        for function_1, function_1_hashes in control_file.functions.items():
            for function_2, function_2_hashes in ecu_file.functions.items():
                for sensor, addresses in sensors.items():
                    if function_1 in addresses:
                        table.push_index(
                            function_1 + ' (' + sensor + ')',
                            function_2,
                            _jaccard_index(function_1_hashes, function_2_hashes)
                        )
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
        json_data = json.load(file, object_pairs_hook=OrderedDict)

        for file_name in json_data:
            ecu_file = EcuFile(file_name, json_data[file_name])

            # Pick out control file
            if ecu_file.name == '27-93-EG33':
                control_file = ecu_file
            else:
                ecu_files.append(ecu_file)

    # Setup Excel sheet
    book = xlsxwriter.Workbook(sys.argv[2])
    tables = _create_tables(control_file, ecu_files)

    # Write all table data to sheets
    for table in tables:
        table.write_results(book)

    book.close()

    print('\nWrote values to {}\n'.format(sys.argv[2]))
    # print('Final results {}%\n'.format(round((float(results[0]) / results[1]) * 100), 2))
