import idaapi
from idaapi import *


# Instructions definition
proc_Instructions = [
      {'name': 'sub', 'feature': CF_USE1 | CF_USE2 | CF_CHG1},
      {'name': 'subleq', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 | CF_JUMP},
]


# This function returns the processor module definition
class subleq_processor(idaapi.processor_t) :  
	version = IDP_INTERFACE_VERSION

	# IDP id
	id = 0x8000 + 1
	
	# Processor features
	flag = PRN_HEX | PR_RNAMESOK | PR_ALIGN_INSN
	
	# short processor names
	# Each name should be shorter than 9 characters
	psnames = ['subleq']

	# long processor names
	# No restriction on name lengthes.
	plnames = ['Subleq Byte code']
	
	cnbits = 8
	dnbits = 8
	
	# number of registers
	regsNum = 0
	
	#dummy
	regNames = ["R0"]
  
	regFirstSreg =  16
	regLastSreg = 17
	segreg_size = 0
	regCodeSreg = 16
	regDataSreg = 17
	instruc_start = 0
	instruc_end = len(proc_Instructions) + 1
	
	# Array of instructions
	instruc = proc_Instructions
	
	assembler = \
	{
			# flag
			'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

			# Assembler name (displayed in menus)
			'name': "Subleq bytecode assembler",
			
			# org directive
            'origin': "org",

			# end directive
			'end': "end",

			# comment string (see also cmnt2)
                'cmnt': ";",

			# ASCII string delimiter
			'ascsep': "\"",

			# ASCII char constant delimiter
			'accsep': "'",

			# ASCII special chars (they can't appear in character and ascii constants)
			'esccodes': "\"'",
			
			#
			#      Data representation (db,dw,...):
			#
			# ASCII string directive
			'a_ascii': "db",

			# byte directive
			'a_byte': "db",

			# word directive
			'a_word': "dw",

			# remove if not allowed
			'a_dword': "dd",

			# remove if not allowed
			'a_qword': "dq",

			# remove if not allowed
			'a_oword': "xmmword",

			# remove if not allowed
			'a_yword': "ymmword",

			# float;  4bytes; remove if not allowed
			'a_float': "dd",

			# double; 8bytes; NULL if not allowed
			'a_double': "dq",

			# long double;    NULL if not allowed
			'a_tbyte': "dt",

			# packed decimal real; remove if not allowed (optional)
			'a_packreal': "",

			# array keyword. the following
			# sequences may appear:
			#      #h - header
			#      #d - size
			#      #v - value
			#      #s(b,w,l,q,f,d,o) - size specifiers
			#                        for byte,word,
			#                            dword,qword,
			#                            float,double,oword
			'a_dups': "#d dup(#v)",

			# uninitialized data directive (should include '%s' for the size of data)
			'a_bss': "%s dup ?",

			# 'equ' Used if AS_UNEQU is set (optional)
			'a_equ': ".equ",

			# 'seg ' prefix (example: push seg seg001)
			'a_seg': "seg",

			# current IP (instruction pointer) symbol in assembler
			'a_curip': "$",

			# "public" name keyword. NULL-gen default, ""-do not generate
			'a_public': "public",

			# "weak"   name keyword. NULL-gen default, ""-do not generate
			'a_weak': "weak",

			# "extrn"  name keyword
			'a_extrn': "extrn",

			# "comm" (communal variable)
			'a_comdef': "",

			# "align" keyword
			'a_align': "align",

			# Left and right braces used in complex expressions
			'lbrace': "(",
			'rbrace': ")",

			# %  mod     assembler time operation
			'a_mod': "%",

			# &  bit and assembler time operation
			'a_band': "&",

			# |  bit or  assembler time operation
			'a_bor': "|",

			# ^  bit xor assembler time operation
			'a_xor': "^",

			# ~  bit not assembler time operation
			'a_bnot': "~",

			# << shift left assembler time operation
			'a_shl': "<<",

			# >> shift right assembler time operation
			'a_shr': ">>",

			# size of type (format string) (optional)
			'a_sizeof_fmt': "size %s",

			'flag2': 0,

			# comment close string (optional)
			# this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
			# then cmnt = "(*" and cmnt2 = "*)"
			'cmnt2': "",

			# low8 operation, should contain %s for the operand (optional fields)
			'low8': "",
			'high8': "",
			'low16': "",
			'high16': "",

			# the include directive (format string) (optional)
			'a_include_fmt': "include %s",

			# if a named item is a structure and displayed  in the verbose (multiline) form then display the name
			# as printf(a_strucname_fmt, typename)
			# (for asms with type checking, e.g. tasm ideal)
			# (optional)
			'a_vstruc_fmt': "",

			# 3-byte data (optional)
			'a_3byte': "",

			# 'rva' keyword for image based offsets (optional)
			# (see nalt.hpp, REFINFO_RVA)
			'a_rva': "rva"
	} # Assembler
	
	
	def outop(self) :
		return 1
	
	def out(self) :
		# Init output buffer
		buf = idaapi.init_output_buffer(1024)
		
		# First, output the instruction mnemonic
		OutMnem()
		
		#Destination
		out_symbol('[')
		OutValue(self.cmd.Operands[0], OOF_ADDR | OOFW_16)
		out_symbol(']')
		

		out_symbol(',')
		OutChar(' ')
		
		#Source
		out_symbol('[')
		OutValue(self.cmd.Operands[1], OOF_ADDR | OOFW_16)
		out_symbol(']')
		
		if self.cmd.itype == self.itype_subleq :
			out_symbol(',')
			OutChar(' ')
			OutValue(self.cmd.Operands[2], OOF_ADDR | OOFW_16)

		# Terminate the output buffer
		term_output_buffer()

		# Emit the line
		cvar.gl_comm = 1
		MakeLine(buf)
	
	def emu(self) :
		if self.cmd.itype == self.itype_sub :
			ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)
		elif self.cmd.itype == self.itype_subleq :
			ua_add_cref(0, self.cmd.Operands[2].addr, fl_JN)
			if self.cmd.Operands[0].addr != self.cmd.Operands[1].addr :
				ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)
		
		return 1
		
	
	def ana(self):
		# Read instruction
		src = ua_next_word()		
		dest = ua_next_word()
		branch = ua_next_word()
		
		self.cmd.size = 6
		
		#Destination operand
		self.cmd.Operands[0].type = o_imm
		self.cmd.Operands[0].addr = dest * 2
		
		#Source operand
		self.cmd.Operands[1].type = o_imm
		self.cmd.Operands[1].addr = src * 2
		
		if branch :
			self.cmd.itype = self.itype_subleq
			self.cmd.Operands[2].type = o_near
			self.cmd.Operands[2].addr = branch * 2
		else :
			self.cmd.itype = self.itype_sub
		

		return self.cmd.size
	
	def __init__(self) :
		idaapi.processor_t.__init__(self)
		
		i = 0
		for inst in proc_Instructions :
			setattr(self, 'itype_' + inst["name"], i)
			i += 1
			
def PROCESSOR_ENTRY():
	return subleq_processor()
