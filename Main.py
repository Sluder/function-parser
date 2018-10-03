#!/usr/bin/python

import os
import sys
import json
import r2pipe

class EcuFile:
	def __init__(self):
		pass

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

		self.analyze(r2)
		self.hashes = self.get_hash()

	def analyze(self, r2):
		"""
		Further analyze function for blocks/instructions
		r2: radare2 instance
		"""
		r2.cmd('s {}'.format(hex(self.start_address)))
		blocks_json = json.loads(r2.cmd('agfj').replace('\r\n', '').decode('utf-8', 'ignore'))[0]['blocks']

		for block_json in blocks_json:
			self.blocks[block_json['offset']] = Block(block_json, r2)

	def get_hash(self):
		"""
		Gets whole hash from function blocks
		"""
		hashes = []

		for offset, block in self.blocks.items():
			hashes.append(block.hash)

		return hashes

class Block:
	def __init__(self, json_obj, r2):
		"""
		Block class constructor
		json_obj: JSON representation of function block
		r2: radare2 instance
		"""
		self.instructions = []
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
		self.hash = self.get_hash()

	def analyze(self, r2):
		"""
		Further analyze function block for instructions/edges
		r2: radare2 instance
		"""
		for instruction_json in self.json['ops']:
			 self.instructions.append(Instruction(instruction_json))

	def get_hash(self):
		"""
		Gets hash of all block instructions opcodes
		"""
		opcodes = ''

		for instruction in self.instructions:
			opcodes += instruction.opcode + '-'

		return hash(opcodes)

class Instruction:
	def __init__(self, json_obj):
		"""
		Instruction class constructor
		json_obj: JSON representation of instruction
		"""
		self.opcode = json_obj['opcode'].split()[0]
		self.address = json_obj['offset']

if __name__ == '__main__':
	"""
	Main function
	"""
	functions = {}
	r2 = None

	try:
		#TODO : support multiple files
		# Ensure file exists, radare doesn't check
		if not os.path.exists(sys.argv[1]):
			raise IOError()

		r2 = r2pipe.open(sys.argv[1], flags=['-2'])
	except IndexError:
		print('[error] No binary specified')
	except IOError:
		print('[error] Unable to open {}'.format(sys.argv[1]))

	r2.cmd('e asm.arch=m7700')
	r2.cmd('aaa')

	functions_json = json.loads(r2.cmd('aflj'))

	# Format JSON dump
	for json_obj in functions_json:
		functions[json_obj['offset']] = Function(json_obj, r2)

	r2.quit()
