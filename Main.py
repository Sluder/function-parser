#!/usr/bin/python

import os
import sys
import json
import r2pipe
from collections import OrderedDict


class EcuFile:
	def __init__(self, filename):
		self.functions = {}
		self.filename = filename

		r2 = r2pipe.open('./bins/' + filename)
		r2.cmd('e asm.arch=m7700')
		r2.cmd('e anal.limits=true')
		r2.cmd('e anal.from=0x9000')
		r2.cmd('e anal.to=0xffff')
		r2.cmd('aaa')

		functions_json = json.loads(r2.cmd('aflj').replace('\r\n', '').decode('utf-8', 'ignore'))

		for json_obj in functions_json:
			self.functions[json_obj['offset']] = Function(json_obj, r2)

		r2.quit()

		print('Created ECU {}'.format(filename))

	def to_string(self):
		for address in self.functions:
			print('\t' + hex(address))


class Function:
	def __init__(self, json_obj, r2):
		"""
		Function class constructor
		json_obj: JSON representation of function
		r2: radare2 instance
		"""
		self.start_address = json_obj['offset']
		self.end_address = int(json_obj['maxbound'])
		self.references = []
		self.blocks = {}

		if 'callrefs' in json_obj:
			for function_reference in json_obj['callrefs']:
				self.references.append(function_reference['addr'])

		#self.analyze(r2)

	def analyze(self, r2):
		"""
		Further analyze function for blocks/instructions
		r2: radare2 instance
		"""
		r2.cmd('s {}'.format(hex(self.start_address)))
		blocks_json = json.loads(r2.cmd('agfj').replace('\r\n', '').decode('utf-8', 'ignore'))[0]['blocks']

		for block_json in blocks_json:
			self.blocks[block_json['offset']] = Block(block_json, r2)


class Block:
	def __init__(self, json_obj, r2):
		"""
		Block class constructor
		json_obj: JSON representation of function block
		r2: radare2 instance
		"""
		self.json = json_obj

		# 'true' and 'false' edges exist
		if 'jump' in json_obj and 'fail' in json_obj:
			self.jmp_true = json_obj['jump']
			self.jmp_false = json_obj['fail']
		# Default to 'true' edge if no false edge
		elif 'jump' not in json_obj and 'fail' in json_obj:
			self.jmp_true = json_obj['fail']
			self.jmp_false = None
		# Basic block
		else:
			self.jmp_true = None
			self.jmp_false = None

		self.analyze(r2)


if __name__ == '__main__':
	"""
	Main function
	"""
	ecu_files = {}

	for filename in os.listdir('./bins'):
		if filename == '722527-1993-USDM-SVX-EG33.bin':
			ecu_files[filename] = EcuFile(filename)
			ecu_files[filename].to_string()
	# functions = {}
	# r2 = None
	#
	#
	#
	# r2.cmd('e asm.arch=m7700')
	# r2.cmd('aaa')
	#
	# functions_json = json.loads(r2.cmd('aflj'))
	#
	# # Format JSON dump
	# for json_obj in functions_json:
	# 	functions[json_obj['offset']] = Function(json_obj, r2)
	#
	# r2.quit()
