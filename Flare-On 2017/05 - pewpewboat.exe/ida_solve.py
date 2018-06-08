#Souhail Hammou - 2018
#############################################
# Steps :
# =====
# 1 + Get the decrypted data from RAX
#			0000000000403EA9                 mov     [rbp+decrypted_data], rax
#
# 2 + Get the mask at offset 0, draw the corresponding board, and extract the coordinates from it. The next steps are necessary to decrypt the next board's data.
#
# 3 + Skip the fgets dynamically and write the coordinates ourselves into rbp+Letter and rbp+Number (Letter => i, Number => j)
# 			0000000000403801                 call    _printf
# 			0000000000403806                 mov     rdx, cs:stdin   ; stream
# 			000000000040380D                 lea     rax, [rbp+Letter]
# 			0000000000403811                 mov     esi, 11h        		<< Breakpoint here to get the ptr in RAX (lazy to calculate it :P)
# 			0000000000403816                 mov     rdi, rax        ; s
# 			0000000000403819                 call    _fgets
# 			000000000040381E 				 test    rax, rax
# 			0000000000403821 				 jz      loc_4038BF
# 			0000000000403827 				 movzx   eax, [rbp+Letter] 
#			0000000000403811                 mov     esi, 11h        ; n 	<< Skip to here and set the coordinates
# 4 - Continue Step 3 until the board is complete
# 
# 5 + Continue execution until the code below, where we need to skip a captcha like function that does not affect the outcome of the program in any way.
# 			0000000000403BD9 				mov     rax, [rbp+decrypted_data] 	<< breakpoint here
# 			0000000000403BDD 				mov     rdi, rax
# 			0000000000403BE0 				call    NoppedFunction
# 			0000000000403BE5 				mov     [rbp+var_50], 1 			<< Skip to here
#
# 6 + Repeat
##############################################
from idc import *

def draw_board(board) :
	text = ""
	for i in range(0,8):
		for j in range(0,8):
			e = board[i][j]
			if e == 1 :
				text += "x"
			else :
				text += " "
		print text
		text = ""

def build_board_from_mask(mask) :
	board = [[0]*8 for i in range(8)]
	for pos in range(0,64):
		if (1 << pos) & mask :
			i = pos / 8
			j = pos % 8
			board[i][j] = 1
	return board

def get_coordinates_from_mask(mask) :
	coordinates = []
	for pos in range(0,64):
		if (1 << pos) & mask :
			i = (pos / 8) + 0x41
			j = (pos % 8) + 0x31
			coordinates.append(chr(i) + chr(j))
	return coordinates


#Setup addresses
decrypted_data_ip = 0x0000000000403EA9
fgets_ip = 0x0000000000403811
coordinates_ip = 0x0000000000403827
captcha_ip = 0x0000000000403BD9
skip_captcha_ip = 0x0000000000403BE5
end = 0x0000000000403EDA

#Setup breakpoints
AddBpt(decrypted_data_ip)
AddBpt(fgets_ip)
AddBpt(captcha_ip)

#Run to the beginning of the program
RunTo(BeginEA())
GetDebuggerEvent(WFNE_SUSP, -1)
ResumeProcess()
GetDebuggerEvent(WFNE_SUSP, -1)

for i in range(100) :
	#Step 1
	decrypted_data_ptr = int(GetRegValue("RAX"))
	print "Decrypted data is at :" + str(decrypted_data_ptr)
	#Step 2
	board_mask = DbgQword(decrypted_data_ptr)
	print "The board mask is : " + str(board_mask)
	coordinates = get_coordinates_from_mask(board_mask)
	print coordinates
	draw_board(build_board_from_mask(board_mask))

	ResumeProcess()
	GetDebuggerEvent(WFNE_SUSP, -1)

	#Steps 3 & 4
	for coord in coordinates :
		coordinates_ptr = int(GetRegValue("RAX"))
		#Set the Letter and Number
		PatchDbgByte(coordinates_ptr,ord(coord[0]))
		PatchDbgByte(coordinates_ptr + 1,ord(coord[1]))
		#Skip fgets
		SetRegValue(coordinates_ip,"RIP")
		ResumeProcess()
		GetDebuggerEvent(WFNE_SUSP, -1)
	
	#Step 5
	SetRegValue(skip_captcha_ip, "RIP")
	ResumeProcess()
	GetDebuggerEvent(WFNE_SUSP, -1)
