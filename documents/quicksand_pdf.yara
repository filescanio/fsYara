rule shellcode_hash__CloseHandle : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  CloseHandle"
		mitre = "T1106"

	strings:
		$h_raw = {66 62 39 37 66 64 30 66}
		$h_hex = { fb97fd0f }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__CreateFileA : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  CreateFileA"
		mitre = "T1106"

	strings:
		$h_raw = {61 35 31 37 30 30 37 63}
		$h_hex = { a517007c }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__CreateProcessA : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  CreateProcessA"
		mitre = "T1106"

	strings:
		$h_raw = {37 32 66 65 62 33 31 36}
		$h_hex = { 72feb316 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__DeleteFileA : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  DeleteFileA"
		mitre = "T1106"

	strings:
		$h_raw = {32 35 62 30 66 66 63 32}
		$h_hex = { 25b0ffc2 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__ExitProcess : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  ExitProcess"
		mitre = "T1106"

	strings:
		$h_raw = {37 65 64 38 65 32 37 33}
		$h_hex = { 7ed8e273 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__ExitThread : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  ExitThread"
		mitre = "T1106"

	strings:
		$h_raw = {65 66 63 65 65 30 36 30}
		$h_hex = { efcee060 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__GetProcAddress : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  GetProcAddress"
		mitre = "T1129"

	strings:
		$h_raw = {61 61 66 63 30 64 37 63}
		$h_hex = { aafc0d7c }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__GetSystemDirectoryA : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  GetSystemDirectoryA"
		mitre = "T1106"

	strings:
		$h_raw = {63 31 37 39 65 35 62 38}
		$h_hex = { c179e5b8 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash___hwrite : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _hwrite"
		mitre = "T1106"

	strings:
		$h_raw = {64 39 38 61 32 33 65 39}
		$h_hex = { d98a23e9 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash___lclose : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _lclose"
		mitre = "T1106"

	strings:
		$h_raw = {35 62 34 63 31 61 64 64}
		$h_hex = { 5b4c1add }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash___lcreat : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _lcreat"
		mitre = "T1106"

	strings:
		$h_raw = {65 61 34 39 38 61 65 38}
		$h_hex = { ea498ae8 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__LoadLibraryA : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  LoadLibraryA"
		mitre = "T1129"

	strings:
		$h_raw = {38 65 34 65 30 65 65 63}
		$h_hex = { 8e4e0eec }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash___lwrite : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _lwrite"
		mitre = "T1106"

	strings:
		$h_raw = {64 62 38 61 32 33 65 39}
		$h_hex = { db8a23e9 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__SetUnhandledExceptionFilter : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  SetUnhandledExceptionFilter"
		mitre = "T1106"

	strings:
		$h_raw = {66 30 38 61 30 34 35 66}
		$h_hex = { f08a045f }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WaitForSingleObject : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WaitForSingleObject"
		mitre = "T1106"

	strings:
		$h_raw = {61 64 64 39 30 35 63 65}
		$h_hex = { add905ce }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WinExec : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WinExec"
		mitre = "T1059.003"

	strings:
		$h_raw = {39 38 66 65 38 61 30 65}
		$h_hex = { 98fe8a0e }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WriteFile : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WriteFile"
		mitre = "T1059"

	strings:
		$h_raw = {31 66 37 39 30 61 65 38}
		$h_hex = { 1f790ae8 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__accept : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  accept"
		mitre = "T1106"

	strings:
		$h_raw = {65 35 34 39 38 36 34 39}
		$h_hex = { e5498649 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__bind : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  bind"
		mitre = "T1106"

	strings:
		$h_raw = {61 34 31 61 37 30 63 37}
		$h_hex = { a41a70c7 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__closesocket : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  closesocket"
		mitre = "T1106"

	strings:
		$h_raw = {65 37 37 39 63 36 37 39}
		$h_hex = { e779c679 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__connect : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  connect"
		mitre = "T1106"

	strings:
		$h_raw = {65 63 66 39 61 61 36 30}
		$h_hex = { ecf9aa60 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__listen : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  listen"
		mitre = "T1106"

	strings:
		$h_raw = {61 34 61 64 32 65 65 39}
		$h_hex = { a4ad2ee9 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__recv : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  recv"
		mitre = "T1106"

	strings:
		$h_raw = {62 36 31 39 31 38 65 37}
		$h_hex = { b61918e7 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__send : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  send"
		mitre = "T1106"

	strings:
		$h_raw = {61 34 31 39 37 30 65 39}
		$h_hex = { a41970e9 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__socket : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  socket"
		mitre = "T1106"

	strings:
		$h_raw = {36 65 30 62 32 66 34 39}
		$h_hex = { 6e0b2f49 }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WSASocketA : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WSASocketA"
		mitre = "T1106"

	strings:
		$h_raw = {64 39 30 39 66 35 61 64}
		$h_hex = { d909f5ad }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__WSAStartup : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  WSAStartup"
		mitre = "T1106"

	strings:
		$h_raw = {63 62 65 64 66 63 33 62}
		$h_hex = { cbedfc3b }

	condition:
		filesize < 1MB and any of them
}

rule shellcode_hash__URLDownloadToFileA : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  URLDownloadToFileA"
		mitre = "T1106"

	strings:
		$h_raw = {33 36 31 61 32 66 37 30}
		$h_hex = { 361a2f70 }

	condition:
		filesize < 1MB and any of them
}

rule suspicious_shellcode_NOP_Sled : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.shellcode NOP Sled"
		mitre = "T1106"

	strings:
		$h_raw = {39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30}
		$h_hex = { 9090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090 }

	condition:
		filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_unescape : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using unescape"
		mitre = "T1027"

	strings:
		$h_reg1 = /une(.{0,6}?)sca(.{0,6}?)pe([^\)]{0,6}?)\(/
		$h_reg2 = /un(.{0,6}?)esc(.{0,6}?)ape([^\)]{0,6}?)\(/
		$h_reg3 = /unesc([\W]{0,6}?)ape/
		$h_reg5 = /unescape([^\)]{0,6}?)\(/
		$h_raw6 = {22 75 22 2c 22 73 22 2c 22 70 22 2c 22 63 22 2c 22 6e 22 2c 22 65 22 2c 22 61 22 2c}
		$h_raw7 = {22 73 22 2c 22 6e 22 2c 22 61 22 2c 22 65 22 2c 22 63 22 2c 22 75 22 2c 22 65 22 2c 22 70 22}

	condition:
		any of them
}

rule suspicious_string_nopblock : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string nopblock"
		mitre = "T1027"

	strings:
		$h_raw1 = {6e 6f 70 62 6c 6f 63 6b}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_eval : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using eval"
		mitre = "T1027"

	strings:
		$h_reg1 = /eval(\s{0,3}?)\(/
		$h_raw2 = {65 76 61 6c 5c}
		$h_raw3 = {65 76 61 6c 2c}
		$h_reg4 = /'e'(.{1,30}?)'va'(.{1,3}?)'l/
		$h_raw5 = {22 6c 22 2c 22 76 22 2c 22 65 22 2c 22 61 22}
		$h_raw6 = {22 65 22 2c 22 6c 22 2c 22 61 22 2c 22 76 22}
		$h_reg7 = /=(\s{0,6}?)eval/

	condition:
		any of them
}

rule suspicious_javascript_object : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript object"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = {2f 4a 61 76 61 53 63 72 69 70 74}
		$h_raw2 = {2f 4a 53 20}

	condition:
		any of them
}

rule suspicious_javascript_in_XFA_block : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript in XFA block"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 6a 61 76 61 73 63 72 69 70 74}
		$h_raw2 = {61 70 70 6c 69 63 61 74 69 6f 6e 23 32 46 78 2d 6a 61 76 61 73 63 72 69 70 74}

	condition:
		any of them
}

rule suspicious_pdf_embedded_PDF_file : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.pdf embedded PDF file"
		mitre = "T1204.002"

	strings:
		$h_raw1 = {61 70 70 6c 69 63 61 74 69 6f 6e 23 32 46 70 64 66}

	condition:
		any of them
}

rule suspicious_obfuscation_toString : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation toString"
		mitre = "T1027"

	strings:
		$h_raw1 = {74 6f 53 74 72 69 6e 67 28}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_substr : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using substr"
		mitre = "T1027"

	strings:
		$h_raw1 = {73 75 62 73 74 72 28}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_String_replace : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using String.replace"
		mitre = "T1027"

	strings:
		$h_reg1 = /'re'(.{1,24}?)'place'/
		$h_raw2 = {2e 72 65 70 6c 61 63 65}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_String_fromCharCode : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using String.fromCharCode"
		mitre = "T1027"

	strings:
		$h_raw1 = {22 72 43 6f 22 2c 22 74 22 2c 22 63 68 61 22 2c 22 22 2c 22 64 65 41 22}
		$h_raw2 = {22 64 65 41 22 2c 22 63 68 61 22 2c 22 72 43 6f 22 2c 22 74 22}
		$h_reg3 = /from([\W]{0,6}?)C([\W]{0,6}?)h([\W]{0,6}?)a(.{0,6}?)r(.{0,6}?)C(.{0,6}?)o([\W]{0,6}?)d([\W]{0,6}?)e/
		$h_raw4 = {2e 66 72 6f 6d 43 68 61 72 43}

	condition:
		any of them
}

rule suspicious_obfuscation_using_substring : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using substring"
		mitre = "T1027"

	strings:
		$h_reg1 = /\.substring(\s{0,3}?)\(/

	condition:
		filesize < 1MB and any of them
}

rule suspicious_obfuscation_using_util_byteToChar : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using util.byteToChar"
		mitre = "T1027"

	strings:
		$h_raw1 = {62 79 74 65 54 6f 43 68 61 72}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_string_Shellcode_NOP_sled : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string Shellcode NOP sled"
		mitre = "T1027"

	strings:
		$h_raw1 = {25 75 39 30 39 30}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_string_heap_spray_shellcode : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string heap spray shellcode"
		mitre = "T1027"

	strings:
		$h_raw1 = {22 25 22 20 2b 20 22 75 22 20 2b 20 22 30 22 20 2b 20 22 63 22 20 2b 20 22 30 22 20 2b 20 22 63 22 20 2b 20 22 25 75 22 20 2b 20 22 30 22 20 2b 20 22 63 22 20 2b 20 22 30 22 20 2b 20 22 63 22}

	condition:
		any of them
}

rule suspicious_string_shellcode : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string shellcode"
		mitre = "T1027"

	strings:
		$h_raw1 = {25 75 34 31 34 31 25 75 34 31 34 31}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_string__Run_Sploit_ : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string -Run_Sploit-"
		mitre = "T1027"

	strings:
		$h_raw1 = {52 75 6e 5f 53 70 6c 6f 69 74}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_string__HeapSpray_ : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string -HeapSpray-"
		mitre = "T1027"

	strings:
		$h_raw1 = {48 65 61 70 53 70 72 61 79}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_flash_writeMultiByte : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash writeMultiByte"
		mitre = "T1027"

	strings:
		$h_raw1 = {77 72 69 74 65 4d 75 6c 74 69 42 79 74 65}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_flash_addFrameScript : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash addFrameScript"
		mitre = "T1027"

	strings:
		$h_raw1 = {61 64 64 46 72 61 6d 65 53 63 72 69 70 74}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_flash_obfuscated_name : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash obfuscated name"
		mitre = "T1027"

	strings:
		$h_raw1 = {2f 52 23 36 39 63 68 4d 23 36 35 23 36 34 69 61 23 35 33 65 23 37 34 74 69 23 36 65 23 36 37 23 37 33 2f}

	condition:
		any of them
}

rule pdf_exploit_FlateDecode_Stream_Predictor_02_Integer_Overflow_CVE_2009_3459 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit FlateDecode Stream Predictor 02 Integer Overflow CVE-2009-3459"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /Predictor 02(\s{0,2}?)\/(\s{0,2}?)Colors 1073741838/

	condition:
		any of them
}

rule pdf_exploit_colors_number_is_high_CVE_2009_3459 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit colors number is high CVE-2009-3459"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/Colors \d{5,15}?/

	condition:
		any of them
}

rule pdf_exploit_URI_directory_traversal : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit URI directory traversal"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /URI.{1,30}?\/\.\.\/\.\./

	condition:
		any of them
}

rule pdf_exploit_URI_directory_traversal_system32 : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit URI directory traversal system32"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /URI.{1,65}?system32/

	condition:
		any of them
}

rule pdf_exploit_execute_EXE_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 10
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit execute EXE file"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)(.{0,64}?)\.exe/

	condition:
		any of them
}

rule pdf_warning_openaction : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 1
		revision = "1"
		date = "July 14 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.warning OpenAction"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/(O|#4F)(p|#70)(e|#65)(n|#6e)(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)/

	condition:
		any of them
}

rule pdf_exploit_access_system32_directory : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit access system32 directory"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)(.{0,64}?)system32/

	condition:
		any of them
}

rule pdf_warning_remote_action : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_active"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit action uri"
		mitre = "T1566.002"

	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)\s*\/(U|#55)(R|#52)(I|49)/
		$h_reg2 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)\s*\/(S|#53)\s*\/(U|#55)(R|#52)(I|49)/

	condition:
		any of them
}

rule pdf_exploit_execute_action_command : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit execute action command"
		mitre = "T1203 T1204.002"

	strings:
		$h_raw1 = {4c 61 75 6e 63 68 2f 54 79 70 65 2f 41 63 74 69 6f 6e 2f 57 69 6e}

	condition:
		any of them
}

rule pdf_exploit_printSeps_memory_heap_corruption_CVE_2010_4091 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit printSeps memory heap corruption CVE-2010-4091"
		mitre = "T1203 T1204.002"

	strings:
		$h_raw1 = {70 72 69 6e 74 53 65 70 73}

	condition:
		filesize < 1MB and any of them
}

rule suspicious_obfuscation_jjencoded_javascript : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation jjencoded javascript"
		mitre = "T1059.007"

	strings:
		$h_raw1 = {3a 2b 2b 24 2c 24 24 24 24 3a}
		$h_raw2 = {24 24 3a 2b 2b 24 2c 24 24 24}

	condition:
		any of them
}

rule suspicious_obfuscation_getAnnots_access_blocks : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation getAnnots access blocks"
		mitre = "T1059.007"

	strings:
		$h_hex1 = {67 [0-2] 65 [0-2] 74 [0-2] 41 [0-2] 6E [0-2] 6E [0-2] 6F [0-2] 74}
		$h_str2 = {((67 65 74 41 6e 6e 6f 74 73) | (67 00 65 00 74 00 41 00 6e 00 6e 00 6f 00 74 00 73 00))}

	condition:
		any of them
}

rule suspicious_obfuscation_info_Trailer_to_access_blocks : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation info.Trailer to access blocks"
		mitre = "T1059.007"

	strings:
		$h_reg1 = /info([\W]{0,4}?)\.([\W]{0,4}?)Trailer/

	condition:
		any of them
}

rule suspicious_obfuscation_using_app_setTimeOut_to_eval_code : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.obfuscation using app.setTimeOut to eval code"
		mitre = "T1059.007"

	strings:
		$h_raw1 = {61 70 70 2e 73 65 74 54 69 6d 65 4f 75 74}

	condition:
		any of them
}

rule suspicious_string__shellcode_ : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string -shellcode-"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = {76 61 72 20 73 68 65 6c 6c 63 6f 64 65}

	condition:
		any of them
}

rule pdf_exploit_Collab_collectEmailInfo_CVE_2008_0655 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit Collab.collectEmailInfo CVE-2008-0655"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /Collabb([\W]{0,6}?).([\W]{0,6}?)collectEmailInfo/
		$h_raw2 = {43 6f 6c 6c 61 62 63 6f 6c 6c 65 63 74 45 6d 61 69 6c 49 6e 66 6f}
		$h_raw3 = {43 6f 6c 6c 61 62 2e 63 6f 6c 6c 65 63 74 45 6d 61 69 6c 49 6e 66 6f}

	condition:
		any of them
}

rule pdf_exploit_Collab_getIcon_CVE_2009_0927 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit Collab.getIcon CVE-2009-0927"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /Collab([\W]{0,6}?).([\W]{0,6}?)getIcon/
		$h_reg2 = /Collab.get(.{1,24}?)Icon/
		$h_raw3 = {43 6f 6c 6c 61 62 2e 67 65 74 49 63 6f 6e}

	condition:
		any of them
}

rule pdf_suspicious_util_printd_used_to_fill_buffers : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.suspicious util.printd used to fill buffers"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = {75 74 69 6c 2e 70 72 69 6e 74 64}

	condition:
		any of them
}

rule pdf_exploit_media_newPlayer_CVE_2009_4324 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit media.newPlayer CVE-2009-4324"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /med(.{1,24}?)ia(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er/
		$h_reg2 = /med(.{1,24}?)ia(.{1,24}?)newPlay(.{1,24}?)er/
		$h_reg3 = /me(.{1,24}?)dia\.(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er/
		$h_reg4 = /mediaa([\W]{0,6}?)newPlayer/
		$h_reg5 = /media(.{1,24}?)newPlayer/
		$h_raw6 = {6d 65 64 69 61 2e 6e 65 77 50 6c 61 79 65 72}

	condition:
		any of them
}

rule pdf_exploit_spell_customDictionaryOpen_CVE_2009_1493 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit spell.customDictionaryOpen CVE-2009-1493"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /spell(.{1,24}?)customDictionaryOpen/
		$h_raw2 = {73 70 65 6c 6c 2e 63 75 73 74 6f 6d 44 69 63 74 69 6f 6e 61 72 79 4f 70 65 6e}

	condition:
		any of them
}

rule pdf_exploit_util_printf_CVE_2008_2992 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit util.printf CVE-2008-2992"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /util(.{1,24}?)printf(.{1,24}?)45000f/

	condition:
		any of them
}

rule pdf_exploit_using_TIFF_overflow_CVE_2010_0188 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit using TIFF overflow CVE-2010-0188"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /contentType=(.{0,6}?)image\/(.{0,30}?)CQkJCQkJCQkJCQkJCQkJCQkJ/
		$h_raw2 = {6b 4a 43 51 2c 6b 4a 43 51 2c 6b 4a 43 51 2c 6b 4a 43 51 2c 6b 4a 43 51 2c 6b 4a 43 51}

	condition:
		any of them
}

rule suspicious_string_TIFF_overflow_exploit_tif_name_CVE_2010_0188 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string TIFF overflow exploit.tif name CVE-2010-0188"
		mitre = "T1203 T1204.002"

	strings:
		$h_raw1 = {65 78 70 6c 6f 69 74 2e 74 69 66}

	condition:
		any of them
}

rule suspicious_string_base_64_nop_sled_used_in_TIFF_overflow_CVE_2010_0188 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string base 64 nop sled used in TIFF overflow CVE-2010-0188"
		mitre = "T1203 T1204.002"

	strings:
		$h_raw1 = {4a 43 51 6b 4a 43 51 6b 4a 43 51 6b 4a 43 51 6b 4a 43 51 6b 4a 43 51 6b 4a 43 51 6b}
		$h_raw2 = {54 55 30 41 4b 67 41 41 49 44 67 4d 6b 41 79 51 44 4a 41 4d 6b 41 79 51 44 4a 41 4d 6b}
		$h_hex3 = { 4A [1-2] 43 [1-2] 51 [1-2] 6B [1-2] 4A [1-2] 43 [1-2] 51 [1-2] 6B}
		$h_raw4 = {2b 50 6a 34 2b 50 6a 34 2b 50 6a 34 2b 50 6a 34 2b 50 6a 34 2b 50 6a 34 2b 50 6a 34 2b 50 6a 34 2b 50 6a 34 2b 50 6a 34 2b 50 6a 34}

	condition:
		any of them
}

rule pdf_exploit_TIFF_overflow_CVE_2010_0188 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit TIFF overflow CVE-2010-0188"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /ImageField1(.{0,6}?)xfa:contentType=(.{0,6}?)image\/tif/
		$h_hex2 = {BB1500070003FE7FB27F0007BB15000711000100ACA80007BB15000700010100ACA80007F772000711000100E2520007545C0007FFFFFFFF000101000000000004010100001000004000000031D70007BB1500075A526A024D15000722A70007BB15000758CD2E3C4D15000722A70007BB150007055A74F44D15000722A70007BB150007B849492A4D15000722A70007BB150007008BFAAF4D15000722A70007BB15000775EA87FE4D15000722A70007BB150007EB0A5FB94D15000722A70007BB150007}

	condition:
		any of them
}

rule pdf_execute_access_system32_directory : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.execute access system32 directory"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)(.{0,36}?)system32/

	condition:
		any of them
}

rule suspicious_string_obfuscated_unicode_NOP_sled : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.string obfuscated unicode NOP sled"
		mitre = "T1027"

	strings:
		$h_raw1 = {4d 39 30 39 30 4d 39 30 39 30 4d 39 30 39 30 4d 39 30 39 30}

	condition:
		any of them
}

rule suspicious_flash_Embedded_Flash : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash Embedded Flash"

	strings:
		$h_reg1 = /^FWS/
		$h_reg2 = /^CWS/
		$h_reg3 = /^SWF/
		$h_hex4 = {0D0A43575309A2D20000789CECBD797C54}
		$h_reg5 = /\x0aFWS/
		$h_reg6 = /\x0aCWS/
		$h_reg7 = /\x0aSWF/

	condition:
		any of them
}

rule suspicious_flash_Embedded_Flash_define_obj : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash Embedded Flash define obj"
		mitre = "T1204.002"

	strings:
		$h_raw1 = {61 70 70 6c 69 63 61 74 69 6f 6e 23 32 46 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68}
		$h_raw2 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68}

	condition:
		any of them
}

rule pdf_exploit_fontfile_SING_table_overflow_CVE_2010_2883_generic : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit fontfile SING table overflow CVE-2010-2883 generic"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = {53 49 4e 47}
		$h_hex2 = { 41414141414141414141 }

	condition:
		$h_reg1 in ( 0 .. 400 ) and $h_hex2 in ( 0 .. 500 )
}

rule pdf_exploit_fontfile_SING_table_overflow_CVE_2010_2883_A : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit fontfile SING table overflow CVE-2010-2883 A"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = {1045086F0000EB4C00000024686D747809C68EB20000B4C4000004306B65726EDC52D5990000BDA000002D8A6C6F6361F3CBD23D0000BB840000021A6D6178700547063A0000EB2C0000002053494E47D9BCC8B50000011C00001DDF706F7374B45A2FBB0000B8F40000028E70726570}

	condition:
		any of them
}

rule flash_exploit_CVE_2011_0609 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit CVE-2011-0609"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = {4657530947CB0000480140005A0000190100441108000000BF141CCB0000000000000010002E00060080804094A8D0A001808004100002000000121212E24130F00931343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134}
		$h_hex2 = {34363537353330394541433730303030373830303036343030303030304338303030303032443031303034343131313830303030303034333032463446344634383630363036303230303031303030304646303931303030303030303033303030313030383630363036303130303032303030303430303030303030424631313235}
		$h_hex3 = {3941303139413031394130313941303139064C6F61646572}

	condition:
		any of them
}

rule flash_exploit_CVE_2011_0611 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit CVE-2011-0611"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = {7772697465427974650541727261799817343635373533304143433035303030303738}
		$h_hex2 = {5131645443737746414142346E453155625778545A52512B743733742B3362744B4E30596E617767552F414452654D5848334777597276757737597A643743674A734A6C76643174374E716D393959576D4B676B5A7674686C68446942556E344D694645453030514659306D456F664A2B4F45504D55594E6F69614C526D4E696A4D45494444665065652B3139663534652B35356E764F63383578376532766732514551504148514C6B45384248683175303937414B7741654943394F6A336579756277574E52793141564A475939326D4777444832794278794147636569424250524348}
		$h_hex3 = {343635373533304143433035303030303738303030353546303030303046413030303030313830313030343431313030303030303030334630334137303530303030393630433030303530303037393543333743313330374642433337433133304531323944303230303443303439443032303031383030383831353030303930303431}
		$h_hex4 = {3063306330633063306330633063306306537472696E6706}
		$h_hex5 = {410042004300440045004600470048004900A18E110064656661756C74}
		$h_hex6 = {00414243444500566B6475686752656D686677317375727772777C73680064656661756C740067657453697A650047647768317375727772777C73680077777273757277}
		$h_raw7 = {41 41 42 34 41 41 56 66 41 41 41 50 6f 41 41 41 47 41 45 41 52 42 45 41 41 41 41 41 50 77 4f 6e 42 51 41 41 6c 67 77 41 42 51 41 48 6c 63 4e 38 45 77 66 37 77 33 77 54 44 68 4b 64 41 67 42 4d 42 4a 30 43 41 42 67 41 69 42 55 41 43 51 42 42 41 45 49 41 51 77 42 45 41 45 55 41 52 67 42 48 41 45 67 41 53 51 43 68 6a 68 45 41 5a 47 56 6d 59 58 56 73 64 41 41 42 41 41 51 71 41 41 49 41 6d 41 47 57 43 67 41 48 57 4d 42 4a 53 41 65 6e 50 37 61 33 59 4a 30 43 41 41 41 41 6d 51 49 41 53 51 42 41 6c 67 55 41 42 78 5a 30 63 41 74 4d 59 70 30 43 41 41 77 41 68 77 45 41 41 78 65 48 41 51 41 42 6c 67 6f 41 42}

	condition:
		any of them
}

rule flash_suspicious_jit_spray : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.suspicious jit_spray"
		mitre = "T1027 T1059.007"

	strings:
		$h_hex1 = {076A69745F65676708}

	condition:
		any of them
}

rule pdf_exploit_U3D_CVE_2011_2462_A : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit U3D CVE-2011-2462 A"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = {066F3A40AE366A4360DFCBEF8C38CA0492794B79E942BD2BB95B866065A4750119DACF6AF72A773CDEF1117533D394744A14734B18A166C20FDE3DED19D4322E}

	condition:
		any of them
}

rule pdf_exploit_PRC_CVE_2011_4369_A : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit PRC CVE-2011-4369 A"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = {ED7C7938945DF8FF9985868677108DA58C922C612A516FA9D182374A8B868AA25284242D8A3296B497B74849D2A210D14EA94654A2452ACA2B29D18268A5B7C5EF7E}

	condition:
		any of them
}

rule flash_exploit_flash_calling_malformed_MP4_CVE_2012_0754 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit flash calling malformed MP4 CVE-2012-0754"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = {537472696E6706586D6C537766094D6F766965436C6970076A69745F656767086368696C645265660D446973706C61794F626A656374074D79566964656F05566964656F044D794E430D4E6574436F6E6E656374696F6E}

	condition:
		any of them
}

rule flash_exploit_MP4_Loader_CVE_2012_0754_B : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit MP4 Loader CVE-2012-0754 B"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = {6D703405566964656F0A6E6574436F6E6E6563740D4E6574436F6E6E656374696F6E096E657453747265616D094E657453747265616D}

	condition:
		any of them
}

rule flash_exploit_MP4_CVE_2012_0754 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.exploit MP4 CVE-2012-0754"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = {6D70343269736F6D000000246D646174018080800E1180808009029F0F808080020001C0101281302A056DC00000000D63707274}

	condition:
		any of them
}

rule pdf_exploit_Sandbox_Bypass_CVE_2013_0641 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit Sandbox Bypass CVE-2013-0641"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /push(.{1,5}?)xfa.datasets.createNode(.{1,5}?)dataValue/

	condition:
		any of them
}

rule pdf_exploit_BMP_RLE_integer_heap_overflow_CVE_2013_2729 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit BMP RLE integer heap overflow CVE-2013-2729"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /image.jpeg(.{1,5}?)Qk0AAAAAAAAAAAAAAABAAAAALAEAAAEAAAABAAgAAQAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAUkdC/
		$h_raw2 = {3c 69 6d 61 67 65 3e 51 6b 30 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 42 41 41 41 41 41 4c 41 45 41 41 41 45 41 41 41 41 42 41 41 67 41 41 51 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 49 41 41 41 41 41 41 41 41 41 55 6b 64 43}

	condition:
		any of them
}

rule pdf_exploit_ToolButton_use_after_free_CVE_2014_0496 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit ToolButton use-after-free CVE-2014-0496"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /function(.{1,24}?)app.addToolButton/
		$h_reg2 = /function(.{1,24}?)app.removeToolButton/

	condition:
		any of them
}

rule suspicious_javascript_addToolButton : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.javascript addToolButton"
		mitre = "T1059.007"

	strings:
		$h_raw1 = {61 70 70 2e 61 64 64 54 6f 6f 6c 42 75 74 74 6f 6e}

	condition:
		any of them
}

rule suspicious_embedded_doc_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded doc file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.doc/

	condition:
		any of them
}

rule suspicious_embedded_xls_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded xls file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.xls/

	condition:
		any of them
}

rule suspicious_embedded_ppt_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded ppt file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.ppt/
		$h_reg2 = /\/Type\/Filespec\/F(.{1,30}?)\.pps/

	condition:
		any of them
}

rule suspicious_embedded_scr_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded scr file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.scr/

	condition:
		any of them
}

rule suspicious_embedded_exe_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded exe file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.exe/

	condition:
		any of them
}

rule suspicious_embedded_bat_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded bat file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.bat/

	condition:
		any of them
}

rule suspicious_embedded_rtf_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded rtf file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.rtf/

	condition:
		any of them
}

rule suspicious_embedded_mso_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded mso file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.mso/

	condition:
		any of them
}

rule suspicious_embedded_html_file : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded html file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.htm/

	condition:
		any of them
}

rule suspicious_embedded_OLE_document_header : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded OLE document header"
		mitre = "T1204.002"

	strings:
		$h_reg1 = { d0 cf 11 e0}

	condition:
		$h_reg1 at 0
}

rule suspicious_embedded_external_content : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.embedded external content"
		mitre = "T1566.002"

	strings:
		$h_raw1 = {2f 53 20 2f 55 52 49}

	condition:
		any of them
}

rule pdf_exploit_Corrupted_JPEG2000_CVE_2018_4990 : hardened
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit Corrupted JPEG2000 CVE-2018-4990"
		mitre = "T1203 T1204.002"

	strings:
		$h_hex1 = { 0C6A5020 200D0A87 0A000004 1D6A7032 68000000 16696864 72000000 20000000 200001FF 07000000 0003FC63 6D617000 }

	condition:
		$h_hex1
}

rule pdf_exploit_using_jbig2decode_CVE_2009_0658 : hardened limited
{
	meta:
		is_exploit = true
		is_warning = false
		is_feature = false
		rank = 5
		revision = "1"
		date = "July 20 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit using JBIG2Decode CVE-2009-0658"
		mitre = "T1203 T1204.002"
		url = "https://www.exploit-db.com/exploits/8099"

	strings:
		$h_raw1 = {4a 42 49 47 32 44 65 63 6f 64 65}
		$h_raw2 = {44 65 63 6f 64 65 20 5b 20 31 20 30 20 5d}
		$h_raw3 = {41 42 43 44 13}

	condition:
		all of them
}

