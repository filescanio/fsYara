import "pe"
import "time"

rule pe_timestamp_in_future : hardened
{
	meta:
		description = "PE TimeDateStamp is set in future"
		score = 50

	condition:
		pe.is_pe and pe.timestamp > time.now ( ) and pe.timestamp - time.now ( ) > 86400
}

import "pe"

rule pe_susp_number_data_directories : hardened
{
	meta:
		description = "PE with non common number of data directories value"
		score = 50

	condition:
		pe.is_pe and pe.number_of_rva_and_sizes != 16
}

import "pe"

rule pe_unusual_entrypoint_section : hardened
{
	meta:
		description = "First section is not entrypoint section"
		score = 50

	condition:
		pe.is_pe and pe.entry_point != 0 and not pe.is_dll ( ) and not ( pe.entry_point >= pe.sections [ 0 ] . raw_data_offset and pe.entry_point < pe.sections [ 0 ] . raw_data_offset + pe.sections [ 0 ] . raw_data_size )
}

import "pe"

rule pe_characteristics_dll_but_not_dll : hardened
{
	meta:
		description = "PE has DLL characteristic flag set but lacks export directory"
		score = 50

	condition:
		pe.is_pe and pe.characteristics & pe.DLL and pe.number_of_exports == 0 and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . name == ".text" or pe.sections [ i ] . name == ".code" )
}

import "pe"

rule pe_number_of_sections_uncommon : hardened
{
	meta:
		description = "PE has an unusual number of sections (<2 or >10)"
		score = 50

	condition:
		pe.is_pe and not pe.is_dll ( ) and ( pe.number_of_sections < 2 or pe.number_of_sections > 10 )
}

import "pe"

rule pe_purely_vrtl_executable_section : hardened
{
	meta:
		description = "PE section is executable, purely vrtl (SizeOfRawData == 0)"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . raw_data_size == 0 and pe.sections [ i ] . virtual_size > 0 and ( pe.sections [ i ] . characteristics & pe.SECTION_CNT_CODE != 0 or pe.sections [ i ] . characteristics & pe.SECTION_MEM_EXECUTE != 0 ) )
}

import "pe"

rule pe_purely_physical_section : hardened
{
	meta:
		description = "PE section is physical-only and will not be mapped in memory"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . raw_data_size > 0 and pe.sections [ i ] . virtual_size == 0 )
}

import "pe"

rule pe_unbalanced_vrtl_physical_rtio : hardened
{
	meta:
		description = "PE section with large difference between physical and vrtl size"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . raw_data_size > 0 and pe.sections [ i ] . virtual_size > 0 and ( ( pe.sections [ i ] . virtual_size > pe.sections [ i ] . raw_data_size + 0x10000 or pe.sections [ i ] . raw_data_size > pe.sections [ i ] . virtual_size + 0x10000 ) and ( pe.sections [ i ] . name != ".data" and pe.sections [ i ] . name != ".idata" and pe.sections [ i ] . name != ".pdata" and pe.sections [ i ] . name != ".rdata" ) ) )
}

import "pe"

rule pe_section_wx : hardened
{
	meta:
		description = "PE section is both executable and writable"

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . characteristics & pe.SECTION_MEM_EXECUTE != 0 and pe.sections [ i ] . characteristics & pe.SECTION_MEM_WRITE != 0 )
}

import "pe"

rule pe_section_rwx : hardened
{
	meta:
		description = "PE section is readable, executable and writable"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . characteristics & pe.SECTION_MEM_READ != 0 and pe.sections [ i ] . characteristics & pe.SECTION_MEM_EXECUTE != 0 and pe.sections [ i ] . characteristics & pe.SECTION_MEM_WRITE != 0 )
}

import "pe"

rule pe_section_no_name : hardened
{
	meta:
		description = "PE section name is empty"

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . name == "" )
}

import "pe"

rule pe_executable_section_and_no_code : hardened
{
	meta:
		description = "PE executable section is flagged as not containing code"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . characteristics & pe.SECTION_MEM_EXECUTE != 0 and pe.sections [ i ] . characteristics & pe.SECTION_CNT_CODE == 0 )
}

import "pe"

rule pe_code_section_and_no_executable : hardened
{
	meta:
		description = "PE section is marked as code but is not executable"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . characteristics & pe.SECTION_CNT_CODE != 0 and pe.sections [ i ] . characteristics & pe.SECTION_MEM_EXECUTE == 0 )
}

import "pe"
import "math"

rule pe_high_ntrpy_section : hardened
{
	meta:
		description = "PE file with section ntrpy higher than 7"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( math.entropy ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) >= 7 )
}

import "pe"

rule pe_overlapping_sections : hardened
{
	meta:
		description = "PE sections have overlapping vrtl or raw addresses"
		score = 50

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( for any j in ( i + 1 .. pe.number_of_sections - 1 ) : ( ( pe.sections [ i ] . virtual_address != 0 and pe.sections [ j ] . virtual_address != 0 and pe.sections [ i ] . virtual_address + pe.sections [ i ] . virtual_size > pe.sections [ j ] . virtual_address ) or ( pe.sections [ i ] . raw_data_offset != 0 and pe.sections [ j ] . raw_data_offset != 0 and pe.sections [ i ] . raw_data_offset + pe.sections [ i ] . raw_data_size > pe.sections [ j ] . raw_data_offset ) ) )
}

import "pe"

rule pe_no_import_table : hardened
{
	meta:
		description = "PE Import Table is missing"

	condition:
		pe.is_pe and not pe.is_dll ( ) and ( pe.number_of_rva_and_sizes <= pe.IMAGE_DIRECTORY_ENTRY_IMPORT or pe.data_directories [ pe.IMAGE_DIRECTORY_ENTRY_IMPORT ] . virtual_address == 0 or pe.data_directories [ pe.IMAGE_DIRECTORY_ENTRY_IMPORT ] . size == 0 )
}

import "pe"

rule pe_zero_imports : hardened
{
	meta:
		description = "PE does not imports functions"

	condition:
		pe.is_pe and not pe.is_dll ( ) and pe.number_of_imports == 0
}

import "pe"

rule pe_gui_and_no_window_apis : hardened
{
	meta:
		description = "PE with SUBSYSTEM_WINDOWS_GUI but no related imports"

	condition:
		pe.is_pe and not pe.is_dll ( ) and pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and ( not pe.imports ( /user32.dll/i , /(CreateWindow|CreateDialogIndirectParam|DialogBoxIndirectParam|DialogBoxParam|DispatchMessage|DefDlgProc|MessageBox|GetDC)/i ) > 0 and not pe.imports ( /mscoree.dll/i , /\_CorExeMain/i ) > 0 )
}

import "pe"

rule pe_dynamic_download_imports : hardened
{
	meta:
		description = "Download API strings but not in import table"
		score = 50

	strings:
		$download_api = /internetreadfile|internetconnect[aw]|\brecvfrom\b/i

	condition:
		pe.is_pe and #download_api > 0 and not ( pe.version_info [ "CompanyName" ] contains "Microsoft" and pe.is_dll ( ) ) and pe.imports ( /wininet.dll/i , /internetreadfile|internetconnect[aw]/i ) == 0 and pe.imports ( /ws2_32.dll/i , /recvfrom/i ) == 0
}

import "pe"

rule pe_dynamic_crypto_imports : hardened
{
	meta:
		description = "Crypto API strings but not in import table"
		score = 50

	strings:
		$crypto_api = /Crypt(ReleaseContext|AcquireContextA|DestroyHash|HashData|DestroyKey|DeriveKey|Encrypt|Decrypt)/i

	condition:
		pe.is_pe and #crypto_api > 0 and pe.imports ( /advapi32.dll/i , /Crypt(ReleaseContext|AcquireContextA|DestroyHash|HashData|DestroyKey|DeriveKey|Encrypt|Decrypt)/i ) == 0
}

import "pe"

rule pe_dynamic_injection_imports : hardened
{
	meta:
		description = "Injection API strings but not in import table"
		score = 50

	strings:
		$injection_api = /(VirtualProtect(Ex)?|VirtualAlloc(Ex(Numa)?)?|ResumeThread|SetThreadContext|FindResourceA|LockResource|LoadResource|Ldr(AccessResource|FindResource_U)|Nt(ResumeThread|AllocateVirtualMemory|MapViewOfSection|ProtectVirtualMemory))/i

	condition:
		pe.is_pe and #injection_api > 3 and pe.imports ( /kernel32.dll/i , /(VirtualProtect(Ex)?|VirtualAlloc(Ex(Numa)?)?|ResumeThread|SetThreadContext|FindResourceA|LockResource|LoadResource)/i ) == 0 and pe.imports ( /ntdll.dll/i , /(Ldr(AccessResource|FindResource_U)|Nt(ResumeThread|AllocateVirtualMemory|MapViewOfSection|ProtectVirtualMemory))/i ) == 0
}

import "pe"
import "time"

rule pe_signature_expired : hardened
{
	meta:
		description = "PE signature has expired"

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_signatures - 1 ) : ( pe.signatures [ i ] . not_after < time.now ( ) )
}

import "pe"
import "time"

rule pe_signature_expires_soon : hardened
{
	meta:
		description = "PE signature expires soon"

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_signatures - 1 ) : ( not pe.signatures [ i ] . not_after < time.now ( ) and pe.signatures [ i ] . not_after < time.now ( ) + 86400 * 15 )
}

import "pe"
import "math"

rule pe_high_ntrpy_resource_no_image : hardened
{
	meta:
		description = "PE with embedded resource with high ntrpy (rcdata)"
		score = 50

	condition:
		pe.is_pe and pe.number_of_resources > 0 and for any i in ( 0 .. pe.number_of_resources - 1 ) : ( pe.resources [ i ] . length > 1024 and pe.resources [ i ] . type == pe.RESOURCE_TYPE_RCDATA and math.entropy ( pe.resources [ i ] . offset , pe.resources [ i ] . length ) >= 7 )
}

import "pe"

rule pe_large_overlay : hardened
{
	meta:
		description = "PE with a large overlay"

	condition:
		pe.is_pe and pe.overlay.size > 20480
}

import "pe"
import "math"

rule pe_high_ntrpy_overlay : hardened
{
	meta:
		description = "PE overlay with high ntrpy"
		score = 50

	strings:
		$cert_crl = {68 74 74 70 3a 2f 2f 63 72 6c 2e}

	condition:
		pe.is_pe and pe.overlay.size > 1024 and $cert_crl in ( pe.overlay.offset..pe.overlay.size ) and math.entropy ( pe.overlay.offset , pe.overlay.size ) >= 7
}

rule pe_embedded_pe : hardened
{
	meta:
		description = "Discover embedded PE files, without relying on easily stripped/modified header strings."
		score = 50

	strings:
		$mz = { 4D 5A }

	condition:
		for any i in ( 1 .. #mz ) : ( @mz [ i ] != 0 and uint32( @mz [ i ] + uint32( @mz [ i ] + 0x3C ) ) == 0x00004550 )
}

import "pe"

rule pe_embedded_x509_cert : hardened limited
{
	meta:
		description = "detect executable that likely have an embedded x509 certificate"
		score = 50

	strings:
		$cert = {((42 45 47 49 4e 20 43 45 52 54 49 46 49 43 41 54 45) | (42 00 45 00 47 00 49 00 4e 00 20 00 43 00 45 00 52 00 54 00 49 00 46 00 49 00 43 00 41 00 54 00 45 00))}
		$cert_xor = {(( 42 45 47 49 4e 20 43 45 52 54 49 46 49 43 41 54 45) |( 43 44 46 48 4f 21 42 44 53 55 48 47 48 42 40 55 44) |( 40 47 45 4b 4c 22 41 47 50 56 4b 44 4b 41 43 56 47) |( 41 46 44 4a 4d 23 40 46 51 57 4a 45 4a 40 42 57 46) |( 46 41 43 4d 4a 24 47 41 56 50 4d 42 4d 47 45 50 41) |( 47 40 42 4c 4b 25 46 40 57 51 4c 43 4c 46 44 51 40) |( 44 43 41 4f 48 26 45 43 54 52 4f 40 4f 45 47 52 43) |( 45 42 40 4e 49 27 44 42 55 53 4e 41 4e 44 46 53 42) |( 4a 4d 4f 41 46 28 4b 4d 5a 5c 41 4e 41 4b 49 5c 4d) |( 4b 4c 4e 40 47 29 4a 4c 5b 5d 40 4f 40 4a 48 5d 4c) |( 48 4f 4d 43 44 2a 49 4f 58 5e 43 4c 43 49 4b 5e 4f) |( 49 4e 4c 42 45 2b 48 4e 59 5f 42 4d 42 48 4a 5f 4e) |( 4e 49 4b 45 42 2c 4f 49 5e 58 45 4a 45 4f 4d 58 49) |( 4f 48 4a 44 43 2d 4e 48 5f 59 44 4b 44 4e 4c 59 48) |( 4c 4b 49 47 40 2e 4d 4b 5c 5a 47 48 47 4d 4f 5a 4b) |( 4d 4a 48 46 41 2f 4c 4a 5d 5b 46 49 46 4c 4e 5b 4a) |( 52 55 57 59 5e 30 53 55 42 44 59 56 59 53 51 44 55) |( 53 54 56 58 5f 31 52 54 43 45 58 57 58 52 50 45 54) |( 50 57 55 5b 5c 32 51 57 40 46 5b 54 5b 51 53 46 57) |( 51 56 54 5a 5d 33 50 56 41 47 5a 55 5a 50 52 47 56) |( 56 51 53 5d 5a 34 57 51 46 40 5d 52 5d 57 55 40 51) |( 57 50 52 5c 5b 35 56 50 47 41 5c 53 5c 56 54 41 50) |( 54 53 51 5f 58 36 55 53 44 42 5f 50 5f 55 57 42 53) |( 55 52 50 5e 59 37 54 52 45 43 5e 51 5e 54 56 43 52) |( 5a 5d 5f 51 56 38 5b 5d 4a 4c 51 5e 51 5b 59 4c 5d) |( 5b 5c 5e 50 57 39 5a 5c 4b 4d 50 5f 50 5a 58 4d 5c) |( 58 5f 5d 53 54 3a 59 5f 48 4e 53 5c 53 59 5b 4e 5f) |( 59 5e 5c 52 55 3b 58 5e 49 4f 52 5d 52 58 5a 4f 5e) |( 5e 59 5b 55 52 3c 5f 59 4e 48 55 5a 55 5f 5d 48 59) |( 5f 58 5a 54 53 3d 5e 58 4f 49 54 5b 54 5e 5c 49 58) |( 5c 5b 59 57 50 3e 5d 5b 4c 4a 57 58 57 5d 5f 4a 5b) |( 5d 5a 58 56 51 3f 5c 5a 4d 4b 56 59 56 5c 5e 4b 5a) |( 62 65 67 69 6e 00 63 65 72 74 69 66 69 63 61 74 65) |( 63 64 66 68 6f 01 62 64 73 75 68 67 68 62 60 75 64) |( 60 67 65 6b 6c 02 61 67 70 76 6b 64 6b 61 63 76 67) |( 61 66 64 6a 6d 03 60 66 71 77 6a 65 6a 60 62 77 66) |( 66 61 63 6d 6a 04 67 61 76 70 6d 62 6d 67 65 70 61) |( 67 60 62 6c 6b 05 66 60 77 71 6c 63 6c 66 64 71 60) |( 64 63 61 6f 68 06 65 63 74 72 6f 60 6f 65 67 72 63) |( 65 62 60 6e 69 07 64 62 75 73 6e 61 6e 64 66 73 62) |( 6a 6d 6f 61 66 08 6b 6d 7a 7c 61 6e 61 6b 69 7c 6d) |( 6b 6c 6e 60 67 09 6a 6c 7b 7d 60 6f 60 6a 68 7d 6c) |( 68 6f 6d 63 64 0a 69 6f 78 7e 63 6c 63 69 6b 7e 6f) |( 69 6e 6c 62 65 0b 68 6e 79 7f 62 6d 62 68 6a 7f 6e) |( 6e 69 6b 65 62 0c 6f 69 7e 78 65 6a 65 6f 6d 78 69) |( 6f 68 6a 64 63 0d 6e 68 7f 79 64 6b 64 6e 6c 79 68) |( 6c 6b 69 67 60 0e 6d 6b 7c 7a 67 68 67 6d 6f 7a 6b) |( 6d 6a 68 66 61 0f 6c 6a 7d 7b 66 69 66 6c 6e 7b 6a) |( 72 75 77 79 7e 10 73 75 62 64 79 76 79 73 71 64 75) |( 73 74 76 78 7f 11 72 74 63 65 78 77 78 72 70 65 74) |( 70 77 75 7b 7c 12 71 77 60 66 7b 74 7b 71 73 66 77) |( 71 76 74 7a 7d 13 70 76 61 67 7a 75 7a 70 72 67 76) |( 76 71 73 7d 7a 14 77 71 66 60 7d 72 7d 77 75 60 71) |( 77 70 72 7c 7b 15 76 70 67 61 7c 73 7c 76 74 61 70) |( 74 73 71 7f 78 16 75 73 64 62 7f 70 7f 75 77 62 73) |( 75 72 70 7e 79 17 74 72 65 63 7e 71 7e 74 76 63 72) |( 7a 7d 7f 71 76 18 7b 7d 6a 6c 71 7e 71 7b 79 6c 7d) |( 7b 7c 7e 70 77 19 7a 7c 6b 6d 70 7f 70 7a 78 6d 7c) |( 78 7f 7d 73 74 1a 79 7f 68 6e 73 7c 73 79 7b 6e 7f) |( 79 7e 7c 72 75 1b 78 7e 69 6f 72 7d 72 78 7a 6f 7e) |( 7e 79 7b 75 72 1c 7f 79 6e 68 75 7a 75 7f 7d 68 79) )}
		$cert_base64 = {((51 6b 56 48 53 55 34 67 51 30 56 53 56 45 6c 47 53 55 4e 42 56 45 55 3d) | (51 00 6b 00 56 00 48 00 53 00 55 00 34 00 67 00 51 00 30 00 56 00 53 00 56 00 45 00 6c 00 47 00 53 00 55 00 4e 00 42 00 56 00 45 00 55 00 3d 00))}
		$cert_flipflop = {((45 42 49 47 20 4e 45 43 54 52 46 49 43 49 54 41 45) | (45 00 42 00 49 00 47 00 20 00 4e 00 45 00 43 00 54 00 52 00 46 00 49 00 43 00 49 00 54 00 41 00 45 00))}
		$cert_reverse = {((45 54 41 43 49 46 49 54 52 45 43 20 4e 49 47 45 42) | (45 00 54 00 41 00 43 00 49 00 46 00 49 00 54 00 52 00 45 00 43 00 20 00 4e 00 49 00 47 00 45 00 42 00))}
		$cert_hex = {((34 32 34 35 34 37 34 39 34 65 32 30 34 33 34 35 35 32 35 34 34 39 34 36 34 39 34 33 34 31 35 34 34 35) | (34 00 32 00 34 00 35 00 34 00 37 00 34 00 39 00 34 00 65 00 32 00 30 00 34 00 33 00 34 00 35 00 35 00 32 00 35 00 34 00 34 00 39 00 34 00 36 00 34 00 39 00 34 00 33 00 34 00 31 00 35 00 34 00 34 00 35 00))}

	condition:
		pe.is_pe and any of them
}

import "pe"

rule pe_resource_reversed_pe : hardened
{
	meta:
		description = "check for MZ at the end of the of any resource"
		score = 75

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_resources - 1 ) : ( uint16be( ( pe.resources [ i ] . offset + pe.resources [ i ] . length ) - 2 ) == 0x5a4d )
}

import "pe"

rule pe_overlay_reversed_pe : hardened
{
	meta:
		description = "check for MZ at the end of the of the overlay"
		score = 75

	condition:
		pe.is_pe and pe.overlay.offset != 0x0 and uint16be( ( pe.overlay.offset + pe.overlay.size ) - 2 ) == 0x5a4d
}

import "pe"

rule pe_resource_base64d_pe : hardened
{
	meta:
		description = "looking for probable base64 encoded PE headers in the resources"
		score = 75

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_resources - 1 ) : ( uint32be( pe.resources [ i ] . offset ) == 0x54567151 and uint32be( pe.resources [ i ] . offset + 4 ) == 0x41414D41 )
}

import "pe"

rule pe_overlay_base64d_pe : hardened
{
	meta:
		description = "looking for probable base64 encoded PE headers in the overlay"
		score = 75

	condition:
		pe.is_pe and pe.overlay.offset != 0x0 and uint32be( pe.overlay.offset ) == 0x54567151 and uint32be( pe.overlay.offset + 4 ) == 0x41414D41
}

import "pe"

rule pe_resource_single_byte_xor_PE : hardened
{
	meta:
		description = "Try the 3rd byte as a XOR key, since typically that byte is zero in a PE, meaning in encoded form it will contain the XOR key"
		score = 75

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_resources - 1 ) : ( uint16( pe.resources [ i ] . offset ) != 0x5a4d and uint8( pe.resources [ i ] . offset ) ^ uint8( pe.resources [ i ] . offset + 3 ) == 0x4d and uint8( pe.resources [ i ] . offset + 1 ) ^ uint8( pe.resources [ i ] . offset + 3 ) == 0x5a )
}

import "pe"

rule pe_overlay_single_byte_xor_PE : hardened
{
	meta:
		description = "Try the 3rd byte as a XOR key, since typically that byte is zero in a PE, meaning in encoded form it will contain the XOR key"
		score = 75

	condition:
		pe.is_pe and pe.overlay.offset != 0x0 and uint16( pe.overlay.offset ) != 0x5a4d and int8 ( pe.overlay.offset ) ^ uint8( pe.overlay.offset + 3 ) == 0x4d and uint8( pe.overlay.offset + 1 ) ^ uint8( pe.overlay.offset + 3 ) == 0x5a
}

rule pe_hex_encoded_pe : hardened limited
{
	meta:
		description = "Check for the bytes typically associated with a PE header, but as strings to detect hex encoding"
		score = 50

	strings:
		$dos_message_hex = {((35 34 36 38 36 39 37 33 32 30 37 30 37 32 36 66 36 37 37 32 36 31 36 64 32 30 36 33 36 31 36 65 36 65 36 66 37 34 32 30 36 32 36 35 32 30 37 32 37 35 36 65 32 30 36 39 36 65 32 30 34 34 34 66 35 33 32 30 36 64 36 66 36 34 36 35) | (35 00 34 00 36 00 38 00 36 00 39 00 37 00 33 00 32 00 30 00 37 00 30 00 37 00 32 00 36 00 66 00 36 00 37 00 37 00 32 00 36 00 31 00 36 00 64 00 32 00 30 00 36 00 33 00 36 00 31 00 36 00 65 00 36 00 65 00 36 00 66 00 37 00 34 00 32 00 30 00 36 00 32 00 36 00 35 00 32 00 30 00 37 00 32 00 37 00 35 00 36 00 65 00 32 00 30 00 36 00 39 00 36 00 65 00 32 00 30 00 34 00 34 00 34 00 66 00 35 00 33 00 32 00 30 00 36 00 64 00 36 00 66 00 36 00 34 00 36 00 35 00))}
		$mz_hex = {((34 44 35 41 39 30 30 30 30 33 30 30) | (34 00 44 00 35 00 41 00 39 00 30 00 30 00 30 00 30 00 33 00 30 00 30 00))}

	condition:
		all of them
}

rule pe_xored_dos_message : hardened limited
{
	meta:
		description = "Check xored dos message"
		score = 50

	strings:
		$xored_dos_message = {(( 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65) |( 55 69 68 72 21 71 73 6e 66 73 60 6c 21 62 60 6f 6f 6e 75 21 63 64 21 73 74 6f 21 68 6f 21 45 4e 52 21 6c 6e 65 64) |( 56 6a 6b 71 22 72 70 6d 65 70 63 6f 22 61 63 6c 6c 6d 76 22 60 67 22 70 77 6c 22 6b 6c 22 46 4d 51 22 6f 6d 66 67) |( 57 6b 6a 70 23 73 71 6c 64 71 62 6e 23 60 62 6d 6d 6c 77 23 61 66 23 71 76 6d 23 6a 6d 23 47 4c 50 23 6e 6c 67 66) |( 50 6c 6d 77 24 74 76 6b 63 76 65 69 24 67 65 6a 6a 6b 70 24 66 61 24 76 71 6a 24 6d 6a 24 40 4b 57 24 69 6b 60 61) |( 51 6d 6c 76 25 75 77 6a 62 77 64 68 25 66 64 6b 6b 6a 71 25 67 60 25 77 70 6b 25 6c 6b 25 41 4a 56 25 68 6a 61 60) |( 52 6e 6f 75 26 76 74 69 61 74 67 6b 26 65 67 68 68 69 72 26 64 63 26 74 73 68 26 6f 68 26 42 49 55 26 6b 69 62 63) |( 53 6f 6e 74 27 77 75 68 60 75 66 6a 27 64 66 69 69 68 73 27 65 62 27 75 72 69 27 6e 69 27 43 48 54 27 6a 68 63 62) |( 5c 60 61 7b 28 78 7a 67 6f 7a 69 65 28 6b 69 66 66 67 7c 28 6a 6d 28 7a 7d 66 28 61 66 28 4c 47 5b 28 65 67 6c 6d) |( 5d 61 60 7a 29 79 7b 66 6e 7b 68 64 29 6a 68 67 67 66 7d 29 6b 6c 29 7b 7c 67 29 60 67 29 4d 46 5a 29 64 66 6d 6c) |( 5e 62 63 79 2a 7a 78 65 6d 78 6b 67 2a 69 6b 64 64 65 7e 2a 68 6f 2a 78 7f 64 2a 63 64 2a 4e 45 59 2a 67 65 6e 6f) |( 5f 63 62 78 2b 7b 79 64 6c 79 6a 66 2b 68 6a 65 65 64 7f 2b 69 6e 2b 79 7e 65 2b 62 65 2b 4f 44 58 2b 66 64 6f 6e) |( 58 64 65 7f 2c 7c 7e 63 6b 7e 6d 61 2c 6f 6d 62 62 63 78 2c 6e 69 2c 7e 79 62 2c 65 62 2c 48 43 5f 2c 61 63 68 69) |( 59 65 64 7e 2d 7d 7f 62 6a 7f 6c 60 2d 6e 6c 63 63 62 79 2d 6f 68 2d 7f 78 63 2d 64 63 2d 49 42 5e 2d 60 62 69 68) |( 5a 66 67 7d 2e 7e 7c 61 69 7c 6f 63 2e 6d 6f 60 60 61 7a 2e 6c 6b 2e 7c 7b 60 2e 67 60 2e 4a 41 5d 2e 63 61 6a 6b) |( 5b 67 66 7c 2f 7f 7d 60 68 7d 6e 62 2f 6c 6e 61 61 60 7b 2f 6d 6a 2f 7d 7a 61 2f 66 61 2f 4b 40 5c 2f 62 60 6b 6a) |( 44 78 79 63 30 60 62 7f 77 62 71 7d 30 73 71 7e 7e 7f 64 30 72 75 30 62 65 7e 30 79 7e 30 54 5f 43 30 7d 7f 74 75) |( 45 79 78 62 31 61 63 7e 76 63 70 7c 31 72 70 7f 7f 7e 65 31 73 74 31 63 64 7f 31 78 7f 31 55 5e 42 31 7c 7e 75 74) |( 46 7a 7b 61 32 62 60 7d 75 60 73 7f 32 71 73 7c 7c 7d 66 32 70 77 32 60 67 7c 32 7b 7c 32 56 5d 41 32 7f 7d 76 77) |( 47 7b 7a 60 33 63 61 7c 74 61 72 7e 33 70 72 7d 7d 7c 67 33 71 76 33 61 66 7d 33 7a 7d 33 57 5c 40 33 7e 7c 77 76) |( 40 7c 7d 67 34 64 66 7b 73 66 75 79 34 77 75 7a 7a 7b 60 34 76 71 34 66 61 7a 34 7d 7a 34 50 5b 47 34 79 7b 70 71) |( 41 7d 7c 66 35 65 67 7a 72 67 74 78 35 76 74 7b 7b 7a 61 35 77 70 35 67 60 7b 35 7c 7b 35 51 5a 46 35 78 7a 71 70) |( 42 7e 7f 65 36 66 64 79 71 64 77 7b 36 75 77 78 78 79 62 36 74 73 36 64 63 78 36 7f 78 36 52 59 45 36 7b 79 72 73) |( 43 7f 7e 64 37 67 65 78 70 65 76 7a 37 74 76 79 79 78 63 37 75 72 37 65 62 79 37 7e 79 37 53 58 44 37 7a 78 73 72) |( 4c 70 71 6b 38 68 6a 77 7f 6a 79 75 38 7b 79 76 76 77 6c 38 7a 7d 38 6a 6d 76 38 71 76 38 5c 57 4b 38 75 77 7c 7d) |( 4d 71 70 6a 39 69 6b 76 7e 6b 78 74 39 7a 78 77 77 76 6d 39 7b 7c 39 6b 6c 77 39 70 77 39 5d 56 4a 39 74 76 7d 7c) |( 4e 72 73 69 3a 6a 68 75 7d 68 7b 77 3a 79 7b 74 74 75 6e 3a 78 7f 3a 68 6f 74 3a 73 74 3a 5e 55 49 3a 77 75 7e 7f) |( 4f 73 72 68 3b 6b 69 74 7c 69 7a 76 3b 78 7a 75 75 74 6f 3b 79 7e 3b 69 6e 75 3b 72 75 3b 5f 54 48 3b 76 74 7f 7e) |( 48 74 75 6f 3c 6c 6e 73 7b 6e 7d 71 3c 7f 7d 72 72 73 68 3c 7e 79 3c 6e 69 72 3c 75 72 3c 58 53 4f 3c 71 73 78 79) |( 49 75 74 6e 3d 6d 6f 72 7a 6f 7c 70 3d 7e 7c 73 73 72 69 3d 7f 78 3d 6f 68 73 3d 74 73 3d 59 52 4e 3d 70 72 79 78) |( 4a 76 77 6d 3e 6e 6c 71 79 6c 7f 73 3e 7d 7f 70 70 71 6a 3e 7c 7b 3e 6c 6b 70 3e 77 70 3e 5a 51 4d 3e 73 71 7a 7b) |( 4b 77 76 6c 3f 6f 6d 70 78 6d 7e 72 3f 7c 7e 71 71 70 6b 3f 7d 7a 3f 6d 6a 71 3f 76 71 3f 5b 50 4c 3f 72 70 7b 7a) |( 74 48 49 53 00 50 52 4f 47 52 41 4d 00 43 41 4e 4e 4f 54 00 42 45 00 52 55 4e 00 49 4e 00 64 6f 73 00 4d 4f 44 45) |( 75 49 48 52 01 51 53 4e 46 53 40 4c 01 42 40 4f 4f 4e 55 01 43 44 01 53 54 4f 01 48 4f 01 65 6e 72 01 4c 4e 45 44) |( 76 4a 4b 51 02 52 50 4d 45 50 43 4f 02 41 43 4c 4c 4d 56 02 40 47 02 50 57 4c 02 4b 4c 02 66 6d 71 02 4f 4d 46 47) |( 77 4b 4a 50 03 53 51 4c 44 51 42 4e 03 40 42 4d 4d 4c 57 03 41 46 03 51 56 4d 03 4a 4d 03 67 6c 70 03 4e 4c 47 46) |( 70 4c 4d 57 04 54 56 4b 43 56 45 49 04 47 45 4a 4a 4b 50 04 46 41 04 56 51 4a 04 4d 4a 04 60 6b 77 04 49 4b 40 41) |( 71 4d 4c 56 05 55 57 4a 42 57 44 48 05 46 44 4b 4b 4a 51 05 47 40 05 57 50 4b 05 4c 4b 05 61 6a 76 05 48 4a 41 40) |( 72 4e 4f 55 06 56 54 49 41 54 47 4b 06 45 47 48 48 49 52 06 44 43 06 54 53 48 06 4f 48 06 62 69 75 06 4b 49 42 43) |( 73 4f 4e 54 07 57 55 48 40 55 46 4a 07 44 46 49 49 48 53 07 45 42 07 55 52 49 07 4e 49 07 63 68 74 07 4a 48 43 42) |( 7c 40 41 5b 08 58 5a 47 4f 5a 49 45 08 4b 49 46 46 47 5c 08 4a 4d 08 5a 5d 46 08 41 46 08 6c 67 7b 08 45 47 4c 4d) |( 7d 41 40 5a 09 59 5b 46 4e 5b 48 44 09 4a 48 47 47 46 5d 09 4b 4c 09 5b 5c 47 09 40 47 09 6d 66 7a 09 44 46 4d 4c) |( 7e 42 43 59 0a 5a 58 45 4d 58 4b 47 0a 49 4b 44 44 45 5e 0a 48 4f 0a 58 5f 44 0a 43 44 0a 6e 65 79 0a 47 45 4e 4f) |( 7f 43 42 58 0b 5b 59 44 4c 59 4a 46 0b 48 4a 45 45 44 5f 0b 49 4e 0b 59 5e 45 0b 42 45 0b 6f 64 78 0b 46 44 4f 4e) |( 78 44 45 5f 0c 5c 5e 43 4b 5e 4d 41 0c 4f 4d 42 42 43 58 0c 4e 49 0c 5e 59 42 0c 45 42 0c 68 63 7f 0c 41 43 48 49) |( 79 45 44 5e 0d 5d 5f 42 4a 5f 4c 40 0d 4e 4c 43 43 42 59 0d 4f 48 0d 5f 58 43 0d 44 43 0d 69 62 7e 0d 40 42 49 48) |( 7a 46 47 5d 0e 5e 5c 41 49 5c 4f 43 0e 4d 4f 40 40 41 5a 0e 4c 4b 0e 5c 5b 40 0e 47 40 0e 6a 61 7d 0e 43 41 4a 4b) |( 7b 47 46 5c 0f 5f 5d 40 48 5d 4e 42 0f 4c 4e 41 41 40 5b 0f 4d 4a 0f 5d 5a 41 0f 46 41 0f 6b 60 7c 0f 42 40 4b 4a) |( 64 58 59 43 10 40 42 5f 57 42 51 5d 10 53 51 5e 5e 5f 44 10 52 55 10 42 45 5e 10 59 5e 10 74 7f 63 10 5d 5f 54 55) |( 65 59 58 42 11 41 43 5e 56 43 50 5c 11 52 50 5f 5f 5e 45 11 53 54 11 43 44 5f 11 58 5f 11 75 7e 62 11 5c 5e 55 54) |( 66 5a 5b 41 12 42 40 5d 55 40 53 5f 12 51 53 5c 5c 5d 46 12 50 57 12 40 47 5c 12 5b 5c 12 76 7d 61 12 5f 5d 56 57) |( 67 5b 5a 40 13 43 41 5c 54 41 52 5e 13 50 52 5d 5d 5c 47 13 51 56 13 41 46 5d 13 5a 5d 13 77 7c 60 13 5e 5c 57 56) |( 60 5c 5d 47 14 44 46 5b 53 46 55 59 14 57 55 5a 5a 5b 40 14 56 51 14 46 41 5a 14 5d 5a 14 70 7b 67 14 59 5b 50 51) |( 61 5d 5c 46 15 45 47 5a 52 47 54 58 15 56 54 5b 5b 5a 41 15 57 50 15 47 40 5b 15 5c 5b 15 71 7a 66 15 58 5a 51 50) |( 62 5e 5f 45 16 46 44 59 51 44 57 5b 16 55 57 58 58 59 42 16 54 53 16 44 43 58 16 5f 58 16 72 79 65 16 5b 59 52 53) |( 63 5f 5e 44 17 47 45 58 50 45 56 5a 17 54 56 59 59 58 43 17 55 52 17 45 42 59 17 5e 59 17 73 78 64 17 5a 58 53 52) |( 6c 50 51 4b 18 48 4a 57 5f 4a 59 55 18 5b 59 56 56 57 4c 18 5a 5d 18 4a 4d 56 18 51 56 18 7c 77 6b 18 55 57 5c 5d) |( 6d 51 50 4a 19 49 4b 56 5e 4b 58 54 19 5a 58 57 57 56 4d 19 5b 5c 19 4b 4c 57 19 50 57 19 7d 76 6a 19 54 56 5d 5c) |( 6e 52 53 49 1a 4a 48 55 5d 48 5b 57 1a 59 5b 54 54 55 4e 1a 58 5f 1a 48 4f 54 1a 53 54 1a 7e 75 69 1a 57 55 5e 5f) |( 6f 53 52 48 1b 4b 49 54 5c 49 5a 56 1b 58 5a 55 55 54 4f 1b 59 5e 1b 49 4e 55 1b 52 55 1b 7f 74 68 1b 56 54 5f 5e) |( 68 54 55 4f 1c 4c 4e 53 5b 4e 5d 51 1c 5f 5d 52 52 53 48 1c 5e 59 1c 4e 49 52 1c 55 52 1c 78 73 6f 1c 51 53 58 59) )}
		$clear_dos_message = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65}

	condition:
		$xored_dos_message and not $clear_dos_message
}

rule pe_base64d_pe : hardened
{
	meta:
		description = "Detects base64 encoded PE files"
		score = 50

	strings:
		$mz_header = {54 56 71 51}
		$this_program = {56 47 68 70 63 79 42 77 63 6d 39 6e 63 6d 46 74}
		$null_bytes = {41 41 41 41 41}

	condition:
		$mz_header and $this_program and #null_bytes > 2
}

rule pe_reversed_base64d_pe : hardened
{
	meta:
		description = "Detects reversed base64 encoded PE files"
		score = 50

	strings:
		$mz_header = {51 71 56 54}
		$this_program = {74 46 6d 63 6e 39 6d 63 77 42 79 63 70 68 47 56}
		$null_bytes = {41 41 41 41 41}

	condition:
		$mz_header and $this_program and #null_bytes > 2
}

rule pe_double_base64d_pe : hardened
{
	meta:
		description = "Detects an executable that has been encoded with base64 twice"
		score = 75

	strings:
		$ = {((56 6b 64 6f 63 47 4e 35 51 6e 64 6a 62 54 6c 75 59 32 31 47 64 45 6c 48 54 6d 68 69 62 54 56 32 5a 45 4e 43 61 56 70 54 51 6e 6c 6b 56 7a 52 6e 59 56 63 30 5a 31 4a 46 4f 56 52 4a 52 7a 46 32 57 6b) | (56 00 6b 00 64 00 6f 00 63 00 47 00 4e 00 35 00 51 00 6e 00 64 00 6a 00 62 00 54 00 6c 00 75 00 59 00 32 00 31 00 47 00 64 00 45 00 6c 00 48 00 54 00 6d 00 68 00 69 00 62 00 54 00 56 00 32 00 5a 00 45 00 4e 00 43 00 61 00 56 00 70 00 54 00 51 00 6e 00 6c 00 6b 00 56 00 7a 00 52 00 6e 00 59 00 56 00 63 00 30 00 5a 00 31 00 4a 00 46 00 4f 00 56 00 52 00 4a 00 52 00 7a 00 46 00 32 00 57 00 6b 00))}
		$ = {((5a 48 61 48 42 6a 65 55 4a 33 59 32 30 35 62 6d 4e 74 52 6e 52 4a 52 30 35 6f 59 6d 30 31 64 6d 52 44 51 6d 6c 61 55 30 4a 35 5a 46 63 30 5a 32 46 58 4e 47 64 53 52 54 6c 55 53 55 63 78 64 6c 70 48) | (5a 00 48 00 61 00 48 00 42 00 6a 00 65 00 55 00 4a 00 33 00 59 00 32 00 30 00 35 00 62 00 6d 00 4e 00 74 00 52 00 6e 00 52 00 4a 00 52 00 30 00 35 00 6f 00 59 00 6d 00 30 00 31 00 64 00 6d 00 52 00 44 00 51 00 6d 00 6c 00 61 00 55 00 30 00 4a 00 35 00 5a 00 46 00 63 00 30 00 5a 00 32 00 46 00 58 00 4e 00 47 00 64 00 53 00 52 00 54 00 6c 00 55 00 53 00 55 00 63 00 78 00 64 00 6c 00 70 00 48 00))}
		$ = {((57 52 32 68 77 59 33 6c 43 64 32 4e 74 4f 57 35 6a 62 55 5a 30 53 55 64 4f 61 47 4a 74 4e 58 5a 6b 51 30 4a 70 57 6c 4e 43 65 57 52 58 4e 47 64 68 56 7a 52 6e 55 6b 55 35 56 45 6c 48 4d 58 5a 61 52) | (57 00 52 00 32 00 68 00 77 00 59 00 33 00 6c 00 43 00 64 00 32 00 4e 00 74 00 4f 00 57 00 35 00 6a 00 62 00 55 00 5a 00 30 00 53 00 55 00 64 00 4f 00 61 00 47 00 4a 00 74 00 4e 00 58 00 5a 00 6b 00 51 00 30 00 4a 00 70 00 57 00 6c 00 4e 00 43 00 65 00 57 00 52 00 58 00 4e 00 47 00 64 00 68 00 56 00 7a 00 52 00 6e 00 55 00 6b 00 55 00 35 00 56 00 45 00 6c 00 48 00 4d 00 58 00 5a 00 61 00 52 00))}
		$ = {((55 6d 39 68 57 45 31 6e 59 30 68 4b 64 6c 6f 7a 53 6d 68 69 55 30 4a 71 57 56 63 31 64 57 49 7a 55 57 64 5a 62 56 56 6e 59 32 35 57 64 55 6c 48 62 48 56 4a 52 56 4a 51 56 58 6c 43 64 47 49 79 55 6d) | (55 00 6d 00 39 00 68 00 57 00 45 00 31 00 6e 00 59 00 30 00 68 00 4b 00 64 00 6c 00 6f 00 7a 00 53 00 6d 00 68 00 69 00 55 00 30 00 4a 00 71 00 57 00 56 00 63 00 31 00 64 00 57 00 49 00 7a 00 55 00 57 00 64 00 5a 00 62 00 56 00 56 00 6e 00 59 00 32 00 35 00 57 00 64 00 55 00 6c 00 48 00 62 00 48 00 56 00 4a 00 52 00 56 00 4a 00 51 00 56 00 58 00 6c 00 43 00 64 00 47 00 49 00 79 00 55 00 6d 00))}
		$ = {((4a 76 59 56 68 4e 5a 32 4e 49 53 6e 5a 61 4d 30 70 6f 59 6c 4e 43 61 6c 6c 58 4e 58 56 69 4d 31 46 6e 57 57 31 56 5a 32 4e 75 56 6e 56 4a 52 32 78 31 53 55 56 53 55 46 56 35 51 6e 52 69 4d 6c 4a 73) | (4a 00 76 00 59 00 56 00 68 00 4e 00 5a 00 32 00 4e 00 49 00 53 00 6e 00 5a 00 61 00 4d 00 30 00 70 00 6f 00 59 00 6c 00 4e 00 43 00 61 00 6c 00 6c 00 58 00 4e 00 58 00 56 00 69 00 4d 00 31 00 46 00 6e 00 57 00 57 00 31 00 56 00 5a 00 32 00 4e 00 75 00 56 00 6e 00 56 00 4a 00 52 00 32 00 78 00 31 00 53 00 55 00 56 00 53 00 55 00 46 00 56 00 35 00 51 00 6e 00 52 00 69 00 4d 00 6c 00 4a 00 73 00))}
		$ = {((53 62 32 46 59 54 57 64 6a 53 45 70 32 57 6a 4e 4b 61 47 4a 54 51 6d 70 5a 56 7a 56 31 59 6a 4e 52 5a 31 6c 74 56 57 64 6a 62 6c 5a 31 53 55 64 73 64 55 6c 46 55 6c 42 56 65 55 4a 30 59 6a 4a 53 62) | (53 00 62 00 32 00 46 00 59 00 54 00 57 00 64 00 6a 00 53 00 45 00 70 00 32 00 57 00 6a 00 4e 00 4b 00 61 00 47 00 4a 00 54 00 51 00 6d 00 70 00 5a 00 56 00 7a 00 56 00 31 00 59 00 6a 00 4e 00 52 00 5a 00 31 00 6c 00 74 00 56 00 57 00 64 00 6a 00 62 00 6c 00 5a 00 31 00 53 00 55 00 64 00 73 00 64 00 55 00 6c 00 46 00 55 00 6c 00 42 00 56 00 65 00 55 00 4a 00 30 00 59 00 6a 00 4a 00 53 00 62 00))}
		$ = {((56 57 46 48 62 48 70 4a 53 45 4a 35 59 6a 4a 6b 65 56 6c 58 4d 47 64 5a 4d 6b 5a 31 59 6d 30 35 4d 45 6c 48 53 6d 78 4a 53 45 6f 78 59 6d 6c 43 63 47 4a 70 51 6b 56 55 4d 55 31 6e 59 6c 63 35 61 31) | (56 00 57 00 46 00 48 00 62 00 48 00 70 00 4a 00 53 00 45 00 4a 00 35 00 59 00 6a 00 4a 00 6b 00 65 00 56 00 6c 00 58 00 4d 00 47 00 64 00 5a 00 4d 00 6b 00 5a 00 31 00 59 00 6d 00 30 00 35 00 4d 00 45 00 6c 00 48 00 53 00 6d 00 78 00 4a 00 53 00 45 00 6f 00 78 00 59 00 6d 00 6c 00 43 00 63 00 47 00 4a 00 70 00 51 00 6b 00 56 00 55 00 4d 00 55 00 31 00 6e 00 59 00 6c 00 63 00 35 00 61 00 31 00))}
		$ = {((56 68 52 32 78 36 53 55 68 43 65 57 49 79 5a 48 6c 5a 56 7a 42 6e 57 54 4a 47 64 57 4a 74 4f 54 42 4a 52 30 70 73 53 55 68 4b 4d 57 4a 70 51 6e 42 69 61 55 4a 46 56 44 46 4e 5a 32 4a 58 4f 57 74 61) | (56 00 68 00 52 00 32 00 78 00 36 00 53 00 55 00 68 00 43 00 65 00 57 00 49 00 79 00 5a 00 48 00 6c 00 5a 00 56 00 7a 00 42 00 6e 00 57 00 54 00 4a 00 47 00 64 00 57 00 4a 00 74 00 4f 00 54 00 42 00 4a 00 52 00 30 00 70 00 73 00 53 00 55 00 68 00 4b 00 4d 00 57 00 4a 00 70 00 51 00 6e 00 42 00 69 00 61 00 55 00 4a 00 46 00 56 00 44 00 46 00 4e 00 5a 00 32 00 4a 00 58 00 4f 00 57 00 74 00 61 00))}
		$ = {((56 59 55 64 73 65 6b 6c 49 51 6e 6c 69 4d 6d 52 35 57 56 63 77 5a 31 6b 79 52 6e 56 69 62 54 6b 77 53 55 64 4b 62 45 6c 49 53 6a 46 69 61 55 4a 77 59 6d 6c 43 52 56 51 78 54 57 64 69 56 7a 6c 72 57) | (56 00 59 00 55 00 64 00 73 00 65 00 6b 00 6c 00 49 00 51 00 6e 00 6c 00 69 00 4d 00 6d 00 52 00 35 00 57 00 56 00 63 00 77 00 5a 00 31 00 6b 00 79 00 52 00 6e 00 56 00 69 00 62 00 54 00 6b 00 77 00 53 00 55 00 64 00 4b 00 62 00 45 00 6c 00 49 00 53 00 6a 00 46 00 69 00 61 00 55 00 4a 00 77 00 59 00 6d 00 6c 00 43 00 52 00 56 00 51 00 78 00 54 00 57 00 64 00 69 00 56 00 7a 00 6c 00 72 00 57 00))}
		$ = {((56 6b 64 6f 63 47 4e 35 51 6e 64 6a 62 54 6c 75 59 32 31 47 64 45 6c 48 4d 54 46 6a 4d 31 46 6e 57 57 31 56 5a 32 4e 75 56 6e 56 4a 53 46 5a 31 57 6b 64 57 65 55 6c 47 5a 48 42 69 61 6b 31 35) | (56 00 6b 00 64 00 6f 00 63 00 47 00 4e 00 35 00 51 00 6e 00 64 00 6a 00 62 00 54 00 6c 00 75 00 59 00 32 00 31 00 47 00 64 00 45 00 6c 00 48 00 4d 00 54 00 46 00 6a 00 4d 00 31 00 46 00 6e 00 57 00 57 00 31 00 56 00 5a 00 32 00 4e 00 75 00 56 00 6e 00 56 00 4a 00 53 00 46 00 5a 00 31 00 57 00 6b 00 64 00 57 00 65 00 55 00 6c 00 47 00 5a 00 48 00 42 00 69 00 61 00 6b 00 31 00 35 00))}
		$ = {((5a 48 61 48 42 6a 65 55 4a 33 59 32 30 35 62 6d 4e 74 52 6e 52 4a 52 7a 45 78 59 7a 4e 52 5a 31 6c 74 56 57 64 6a 62 6c 5a 31 53 55 68 57 64 56 70 48 56 6e 6c 4a 52 6d 52 77 59 6d 70 4e 65) | (5a 00 48 00 61 00 48 00 42 00 6a 00 65 00 55 00 4a 00 33 00 59 00 32 00 30 00 35 00 62 00 6d 00 4e 00 74 00 52 00 6e 00 52 00 4a 00 52 00 7a 00 45 00 78 00 59 00 7a 00 4e 00 52 00 5a 00 31 00 6c 00 74 00 56 00 57 00 64 00 6a 00 62 00 6c 00 5a 00 31 00 53 00 55 00 68 00 57 00 64 00 56 00 70 00 48 00 56 00 6e 00 6c 00 4a 00 52 00 6d 00 52 00 77 00 59 00 6d 00 70 00 4e 00 65 00))}
		$ = {((57 52 32 68 77 59 33 6c 43 64 32 4e 74 4f 57 35 6a 62 55 5a 30 53 55 63 78 4d 57 4d 7a 55 57 64 5a 62 56 56 6e 59 32 35 57 64 55 6c 49 56 6e 56 61 52 31 5a 35 53 55 5a 6b 63 47 4a 71 54 58) | (57 00 52 00 32 00 68 00 77 00 59 00 33 00 6c 00 43 00 64 00 32 00 4e 00 74 00 4f 00 57 00 35 00 6a 00 62 00 55 00 5a 00 30 00 53 00 55 00 63 00 78 00 4d 00 57 00 4d 00 7a 00 55 00 57 00 64 00 5a 00 62 00 56 00 56 00 6e 00 59 00 32 00 35 00 57 00 64 00 55 00 6c 00 49 00 56 00 6e 00 56 00 61 00 52 00 31 00 5a 00 35 00 53 00 55 00 5a 00 6b 00 63 00 47 00 4a 00 71 00 54 00 58 00))}
		$ = {((55 6d 39 68 57 45 31 6e 59 30 68 4b 64 6c 6f 7a 53 6d 68 69 55 30 4a 30 5a 46 68 4f 4d 45 6c 48 53 6d 78 4a 53 45 6f 78 59 6d 6c 43 4d 57 4a 74 55 6d 78 6a 61 55 4a 59 59 56 63 30 65 6b) | (55 00 6d 00 39 00 68 00 57 00 45 00 31 00 6e 00 59 00 30 00 68 00 4b 00 64 00 6c 00 6f 00 7a 00 53 00 6d 00 68 00 69 00 55 00 30 00 4a 00 30 00 5a 00 46 00 68 00 4f 00 4d 00 45 00 6c 00 48 00 53 00 6d 00 78 00 4a 00 53 00 45 00 6f 00 78 00 59 00 6d 00 6c 00 43 00 4d 00 57 00 4a 00 74 00 55 00 6d 00 78 00 6a 00 61 00 55 00 4a 00 59 00 59 00 56 00 63 00 30 00 65 00 6b 00))}
		$ = {((4a 76 59 56 68 4e 5a 32 4e 49 53 6e 5a 61 4d 30 70 6f 59 6c 4e 43 64 47 52 59 54 6a 42 4a 52 30 70 73 53 55 68 4b 4d 57 4a 70 51 6a 46 69 62 56 4a 73 59 32 6c 43 57 47 46 58 4e 48 70 4e) | (4a 00 76 00 59 00 56 00 68 00 4e 00 5a 00 32 00 4e 00 49 00 53 00 6e 00 5a 00 61 00 4d 00 30 00 70 00 6f 00 59 00 6c 00 4e 00 43 00 64 00 47 00 52 00 59 00 54 00 6a 00 42 00 4a 00 52 00 30 00 70 00 73 00 53 00 55 00 68 00 4b 00 4d 00 57 00 4a 00 70 00 51 00 6a 00 46 00 69 00 62 00 56 00 4a 00 73 00 59 00 32 00 6c 00 43 00 57 00 47 00 46 00 58 00 4e 00 48 00 70 00 4e 00))}
		$ = {((53 62 32 46 59 54 57 64 6a 53 45 70 32 57 6a 4e 4b 61 47 4a 54 51 6e 52 6b 57 45 34 77 53 55 64 4b 62 45 6c 49 53 6a 46 69 61 55 49 78 59 6d 31 53 62 47 4e 70 51 6c 68 68 56 7a 52 36 54) | (53 00 62 00 32 00 46 00 59 00 54 00 57 00 64 00 6a 00 53 00 45 00 70 00 32 00 57 00 6a 00 4e 00 4b 00 61 00 47 00 4a 00 54 00 51 00 6e 00 52 00 6b 00 57 00 45 00 34 00 77 00 53 00 55 00 64 00 4b 00 62 00 45 00 6c 00 49 00 53 00 6a 00 46 00 69 00 61 00 55 00 49 00 78 00 59 00 6d 00 31 00 53 00 62 00 47 00 4e 00 70 00 51 00 6c 00 68 00 68 00 56 00 7a 00 52 00 36 00 54 00))}
		$ = {((56 57 46 48 62 48 70 4a 53 45 4a 35 59 6a 4a 6b 65 56 6c 58 4d 47 64 69 57 46 5a 36 5a 45 4e 43 61 56 70 54 51 6e 6c 6b 56 7a 52 6e 5a 46 63 31 61 31 70 59 53 57 64 57 4d 6d 78 31 54 58) | (56 00 57 00 46 00 48 00 62 00 48 00 70 00 4a 00 53 00 45 00 4a 00 35 00 59 00 6a 00 4a 00 6b 00 65 00 56 00 6c 00 58 00 4d 00 47 00 64 00 69 00 57 00 46 00 5a 00 36 00 5a 00 45 00 4e 00 43 00 61 00 56 00 70 00 54 00 51 00 6e 00 6c 00 6b 00 56 00 7a 00 52 00 6e 00 5a 00 46 00 63 00 31 00 61 00 31 00 70 00 59 00 53 00 57 00 64 00 57 00 4d 00 6d 00 78 00 31 00 54 00 58 00))}
		$ = {((56 68 52 32 78 36 53 55 68 43 65 57 49 79 5a 48 6c 5a 56 7a 42 6e 59 6c 68 57 65 6d 52 44 51 6d 6c 61 55 30 4a 35 5a 46 63 30 5a 32 52 58 4e 57 74 61 57 45 6c 6e 56 6a 4a 73 64 55 31 36) | (56 00 68 00 52 00 32 00 78 00 36 00 53 00 55 00 68 00 43 00 65 00 57 00 49 00 79 00 5a 00 48 00 6c 00 5a 00 56 00 7a 00 42 00 6e 00 59 00 6c 00 68 00 57 00 65 00 6d 00 52 00 44 00 51 00 6d 00 6c 00 61 00 55 00 30 00 4a 00 35 00 5a 00 46 00 63 00 30 00 5a 00 32 00 52 00 58 00 4e 00 57 00 74 00 61 00 57 00 45 00 6c 00 6e 00 56 00 6a 00 4a 00 73 00 64 00 55 00 31 00 36 00))}
		$ = {((56 59 55 64 73 65 6b 6c 49 51 6e 6c 69 4d 6d 52 35 57 56 63 77 5a 32 4a 59 56 6e 70 6b 51 30 4a 70 57 6c 4e 43 65 57 52 58 4e 47 64 6b 56 7a 56 72 57 6c 68 4a 5a 31 59 79 62 48 56 4e 65) | (56 00 59 00 55 00 64 00 73 00 65 00 6b 00 6c 00 49 00 51 00 6e 00 6c 00 69 00 4d 00 6d 00 52 00 35 00 57 00 56 00 63 00 77 00 5a 00 32 00 4a 00 59 00 56 00 6e 00 70 00 6b 00 51 00 30 00 4a 00 70 00 57 00 6c 00 4e 00 43 00 65 00 57 00 52 00 58 00 4e 00 47 00 64 00 6b 00 56 00 7a 00 56 00 72 00 57 00 6c 00 68 00 4a 00 5a 00 31 00 59 00 79 00 62 00 48 00 56 00 4e 00 65 00))}

	condition:
		1 of them
}

