import "time"
import "pe"

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

import "dotnet"
import "pe"

rule pe_characteristics_dll_but_not_dll : hardened
{
	meta:
		description = "PE has DLL characteristic flag set but lacks export directory"
		score = 50

	condition:
		not dotnet.is_dotnet and pe.is_pe and pe.characteristics & pe.DLL and pe.number_of_exports == 0 and for any section in pe.sections : ( section.name == ".text" or section.name == ".code" )
}

import "dotnet"
import "pe"

rule pe_number_of_sections_uncommon : hardened
{
	meta:
		description = "PE has an unusual number of sections (<2 or >10)"
		score = 50

	condition:
		not dotnet.is_dotnet and pe.is_pe and not pe.is_dll ( ) and ( pe.number_of_sections < 2 or pe.number_of_sections > 10 )
}

import "pe"

rule pe_purely_vrtl_executable_section : hardened
{
	meta:
		description = "PE section is executable, purely vrtl (SizeOfRawData == 0)"
		score = 50

	condition:
		pe.is_pe and for any section in pe.sections : ( section.raw_data_size == 0 and section.virtual_size > 0 and ( section.characteristics & pe.SECTION_CNT_CODE != 0 or section.characteristics & pe.SECTION_MEM_EXECUTE != 0 ) )
}

import "pe"

rule pe_purely_physical_section : hardened
{
	meta:
		description = "PE section is physical-only and will not be mapped in memory"
		score = 50

	condition:
		pe.is_pe and for any section in pe.sections : ( section.raw_data_size > 0 and section.virtual_size == 0 )
}

import "pe"

rule pe_unbalanced_vrtl_physical_ratio : hardened
{
	meta:
		description = "PE section with large difference between physical and vrtl size"
		score = 50

	condition:
		pe.is_pe and for any section in pe.sections : ( section.raw_data_size > 0 and section.virtual_size > 0 and ( section.virtual_size > section.raw_data_size + 0x10000 or section.raw_data_size > section.virtual_size + 0x10000 ) )
}

import "pe"

rule pe_section_wx : hardened
{
	meta:
		description = "PE section is both executable and writable"

	condition:
		pe.is_pe and for any section in pe.sections : ( section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and section.characteristics & pe.SECTION_MEM_WRITE != 0 )
}

import "pe"

rule pe_section_rwx : hardened
{
	meta:
		description = "PE section is readable, executable and writable"
		score = 50

	condition:
		pe.is_pe and for any section in pe.sections : ( section.characteristics & pe.SECTION_MEM_READ != 0 and section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and section.characteristics & pe.SECTION_MEM_WRITE != 0 )
}

import "pe"

rule pe_section_no_name : hardened
{
	meta:
		description = "PE section name is empty"

	condition:
		pe.is_pe and for any section in pe.sections : ( section.name == "" )
}

import "pe"

rule pe_executable_section_and_no_code : hardened
{
	meta:
		description = "PE executable section is flagged as not containing code"
		score = 50

	condition:
		pe.is_pe and for any section in pe.sections : ( section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and section.characteristics & pe.SECTION_CNT_CODE == 0 )
}

import "pe"

rule pe_code_section_and_no_executable : hardened
{
	meta:
		description = "PE section is marked as code but is not executable"
		score = 50

	condition:
		pe.is_pe and for any section in pe.sections : ( section.characteristics & pe.SECTION_CNT_CODE != 0 and section.characteristics & pe.SECTION_MEM_EXECUTE == 0 )
}

import "math"
import "pe"

rule pe_high_ntrpy_section : hardened
{
	meta:
		description = "PE file with section ntrpy higher than 7"
		score = 50

	condition:
		pe.is_pe and for any section in pe.sections : ( math.entropy ( section.raw_data_offset , section.raw_data_size ) >= 7 )
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

import "dotnet"
import "pe"

rule pe_no_import_table : hardened
{
	meta:
		description = "PE Import Table is missing"

	condition:
		not dotnet.is_dotnet and pe.is_pe and not pe.is_dll ( ) and ( pe.number_of_rva_and_sizes <= pe.IMAGE_DIRECTORY_ENTRY_IMPORT or pe.data_directories [ pe.IMAGE_DIRECTORY_ENTRY_IMPORT ] . virtual_address == 0 or pe.data_directories [ pe.IMAGE_DIRECTORY_ENTRY_IMPORT ] . size == 0 )
}

import "dotnet"
import "pe"

rule pe_zero_imports : hardened
{
	meta:
		description = "PE does not imports functions"

	condition:
		not dotnet.is_dotnet and pe.is_pe and not pe.is_dll ( ) and pe.number_of_imported_functions == 0
}

import "dotnet"
import "pe"

rule pe_very_low_imports : hardened
{
	meta:
		description = "PE imports few functions"

	condition:
		not dotnet.is_dotnet and pe.is_pe and not pe.is_dll ( ) and pe.number_of_imported_functions <= 5
}

import "pe"

rule pe_imports_by_ordinal : hardened
{
	meta:
		description = "Detect PE imports using function ordinals (no named imports)"

	condition:
		pe.is_pe and for any i in ( 0 .. pe.number_of_imports - 1 ) : ( for any function in pe.import_details [ i ] . functions : ( function.name == "" and function.ordinal != 0 ) )
}

import "dotnet"
import "pe"

rule pe_gui_and_no_window_apis : hardened
{
	meta:
		description = "PE with SUBSYSTEM_WINDOWS_GUI but no related imports"

	condition:
		not dotnet.is_dotnet and pe.is_pe and not pe.is_dll ( ) and pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and ( not pe.imports ( /user32.dll/i , /(CreateWindow|CreateDialogIndirectParam|DialogBoxIndirectParam|DialogBoxParam|DispatchMessage|DefDlgProc|MessageBox|GetDC)/i ) > 0 and not pe.imports ( /mscoree.dll/i , /\_CorExeMain/i ) > 0 )
}

import "pe"

rule pe_dynamic_api_resolution_imports : hardened
{
	meta:
		description = "PE imports few functions, including LoadLibrary and GetProcAddress"

	condition:
		pe.is_pe and pe.number_of_imported_functions <= 5 and pe.imports ( /kernel32.dll/i , /loadlibrary(a|w)|getprocaddress/i ) == 2
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

import "time"
import "pe"

rule pe_signature_expired : hardened
{
	meta:
		description = "PE signature has expired"

	condition:
		pe.is_pe and for any signature in pe.signatures : ( signature.not_after < time.now ( ) )
}

import "time"
import "pe"

rule pe_signature_expires_soon : hardened
{
	meta:
		description = "PE signature expires soon"

	condition:
		pe.is_pe and for any signature in pe.signatures : ( not signature.not_after < time.now ( ) and signature.not_after < time.now ( ) + 86400 * 15 )
}

import "math"
import "pe"

rule pe_high_ntrpy_resource_no_image : hardened
{
	meta:
		description = "PE with embedded resource with high ntrpy (rcdata)"
		score = 50

	condition:
		pe.is_pe and pe.number_of_resources > 0 and for any resource in pe.resources : ( resource.length > 1024 and resource.type == pe.RESOURCE_TYPE_RCDATA and math.entropy ( resource.offset , resource.length ) >= 7 )
}

import "pe"

rule pe_large_overlay : hardened
{
	meta:
		description = "PE with a large overlay"
		score = 50

	condition:
		pe.is_pe and pe.overlay.size > 20480
}

import "math"
import "pe"

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
		$cert_xor = {(( 43 44 46 48 4f 21 42 44 53 55 48 47 48 42 40 55 44) |( 40 47 45 4b 4c 22 41 47 50 56 4b 44 4b 41 43 56 47) |( 41 46 44 4a 4d 23 40 46 51 57 4a 45 4a 40 42 57 46) |( 46 41 43 4d 4a 24 47 41 56 50 4d 42 4d 47 45 50 41) |( 47 40 42 4c 4b 25 46 40 57 51 4c 43 4c 46 44 51 40) |( 44 43 41 4f 48 26 45 43 54 52 4f 40 4f 45 47 52 43) |( 45 42 40 4e 49 27 44 42 55 53 4e 41 4e 44 46 53 42) |( 4a 4d 4f 41 46 28 4b 4d 5a 5c 41 4e 41 4b 49 5c 4d) |( 4b 4c 4e 40 47 29 4a 4c 5b 5d 40 4f 40 4a 48 5d 4c) |( 48 4f 4d 43 44 2a 49 4f 58 5e 43 4c 43 49 4b 5e 4f) |( 49 4e 4c 42 45 2b 48 4e 59 5f 42 4d 42 48 4a 5f 4e) |( 4e 49 4b 45 42 2c 4f 49 5e 58 45 4a 45 4f 4d 58 49) |( 4f 48 4a 44 43 2d 4e 48 5f 59 44 4b 44 4e 4c 59 48) |( 4c 4b 49 47 40 2e 4d 4b 5c 5a 47 48 47 4d 4f 5a 4b) |( 4d 4a 48 46 41 2f 4c 4a 5d 5b 46 49 46 4c 4e 5b 4a) |( 52 55 57 59 5e 30 53 55 42 44 59 56 59 53 51 44 55) |( 53 54 56 58 5f 31 52 54 43 45 58 57 58 52 50 45 54) |( 50 57 55 5b 5c 32 51 57 40 46 5b 54 5b 51 53 46 57) |( 51 56 54 5a 5d 33 50 56 41 47 5a 55 5a 50 52 47 56) |( 56 51 53 5d 5a 34 57 51 46 40 5d 52 5d 57 55 40 51) |( 57 50 52 5c 5b 35 56 50 47 41 5c 53 5c 56 54 41 50) |( 54 53 51 5f 58 36 55 53 44 42 5f 50 5f 55 57 42 53) |( 55 52 50 5e 59 37 54 52 45 43 5e 51 5e 54 56 43 52) |( 5a 5d 5f 51 56 38 5b 5d 4a 4c 51 5e 51 5b 59 4c 5d) |( 5b 5c 5e 50 57 39 5a 5c 4b 4d 50 5f 50 5a 58 4d 5c) |( 58 5f 5d 53 54 3a 59 5f 48 4e 53 5c 53 59 5b 4e 5f) |( 59 5e 5c 52 55 3b 58 5e 49 4f 52 5d 52 58 5a 4f 5e) |( 5e 59 5b 55 52 3c 5f 59 4e 48 55 5a 55 5f 5d 48 59) |( 5f 58 5a 54 53 3d 5e 58 4f 49 54 5b 54 5e 5c 49 58) |( 5c 5b 59 57 50 3e 5d 5b 4c 4a 57 58 57 5d 5f 4a 5b) |( 5d 5a 58 56 51 3f 5c 5a 4d 4b 56 59 56 5c 5e 4b 5a) |( 62 65 67 69 6e 00 63 65 72 74 69 66 69 63 61 74 65) |( 63 64 66 68 6f 01 62 64 73 75 68 67 68 62 60 75 64) |( 60 67 65 6b 6c 02 61 67 70 76 6b 64 6b 61 63 76 67) |( 61 66 64 6a 6d 03 60 66 71 77 6a 65 6a 60 62 77 66) |( 66 61 63 6d 6a 04 67 61 76 70 6d 62 6d 67 65 70 61) |( 67 60 62 6c 6b 05 66 60 77 71 6c 63 6c 66 64 71 60) |( 64 63 61 6f 68 06 65 63 74 72 6f 60 6f 65 67 72 63) |( 65 62 60 6e 69 07 64 62 75 73 6e 61 6e 64 66 73 62) |( 6a 6d 6f 61 66 08 6b 6d 7a 7c 61 6e 61 6b 69 7c 6d) |( 6b 6c 6e 60 67 09 6a 6c 7b 7d 60 6f 60 6a 68 7d 6c) |( 68 6f 6d 63 64 0a 69 6f 78 7e 63 6c 63 69 6b 7e 6f) |( 69 6e 6c 62 65 0b 68 6e 79 7f 62 6d 62 68 6a 7f 6e) |( 6e 69 6b 65 62 0c 6f 69 7e 78 65 6a 65 6f 6d 78 69) |( 6f 68 6a 64 63 0d 6e 68 7f 79 64 6b 64 6e 6c 79 68) |( 6c 6b 69 67 60 0e 6d 6b 7c 7a 67 68 67 6d 6f 7a 6b) |( 6d 6a 68 66 61 0f 6c 6a 7d 7b 66 69 66 6c 6e 7b 6a) |( 72 75 77 79 7e 10 73 75 62 64 79 76 79 73 71 64 75) |( 73 74 76 78 7f 11 72 74 63 65 78 77 78 72 70 65 74) |( 70 77 75 7b 7c 12 71 77 60 66 7b 74 7b 71 73 66 77) |( 71 76 74 7a 7d 13 70 76 61 67 7a 75 7a 70 72 67 76) |( 76 71 73 7d 7a 14 77 71 66 60 7d 72 7d 77 75 60 71) |( 77 70 72 7c 7b 15 76 70 67 61 7c 73 7c 76 74 61 70) |( 74 73 71 7f 78 16 75 73 64 62 7f 70 7f 75 77 62 73) |( 75 72 70 7e 79 17 74 72 65 63 7e 71 7e 74 76 63 72) |( 7a 7d 7f 71 76 18 7b 7d 6a 6c 71 7e 71 7b 79 6c 7d) |( 7b 7c 7e 70 77 19 7a 7c 6b 6d 70 7f 70 7a 78 6d 7c) |( 78 7f 7d 73 74 1a 79 7f 68 6e 73 7c 73 79 7b 6e 7f) |( 79 7e 7c 72 75 1b 78 7e 69 6f 72 7d 72 78 7a 6f 7e) |( 7e 79 7b 75 72 1c 7f 79 6e 68 75 7a 75 7f 7d 68 79) |( 7f 78 7a 74 73 1d 7e 78 6f 69 74 7b 74 7e 7c 69 78) )}
		$cert_base64 = {42 45 47 49 4e 20 43 45 52 54 49 46 49 43 41 54 45}
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
		pe.is_pe and for any resource in pe.resources : ( uint16be( ( resource.offset + resource.length ) - 2 ) == 0x5a4d )
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
		pe.is_pe and for any resource in pe.resources : ( uint32be( resource.offset ) == 0x54567151 and uint32be( resource.offset + 4 ) == 0x41414D41 )
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

	condition:
		pe.is_pe and for any resource in pe.resources : ( uint16( resource.offset ) != 0x5a4d and uint8( resource.offset ) ^ uint8( resource.offset + 3 ) == 0x4d and uint8( resource.offset + 1 ) ^ uint8( resource.offset + 3 ) == 0x5a )
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
		$dos_message = {(( 55 69 68 72 21 71 73 6e 66 73 60 6c 21 62 60 6f 6f 6e 75 21 63 64 21 73 74 6f 21 68 6f 21 45 4e 52 21 6c 6e 65 64) |( 56 6a 6b 71 22 72 70 6d 65 70 63 6f 22 61 63 6c 6c 6d 76 22 60 67 22 70 77 6c 22 6b 6c 22 46 4d 51 22 6f 6d 66 67) |( 57 6b 6a 70 23 73 71 6c 64 71 62 6e 23 60 62 6d 6d 6c 77 23 61 66 23 71 76 6d 23 6a 6d 23 47 4c 50 23 6e 6c 67 66) |( 50 6c 6d 77 24 74 76 6b 63 76 65 69 24 67 65 6a 6a 6b 70 24 66 61 24 76 71 6a 24 6d 6a 24 40 4b 57 24 69 6b 60 61) |( 51 6d 6c 76 25 75 77 6a 62 77 64 68 25 66 64 6b 6b 6a 71 25 67 60 25 77 70 6b 25 6c 6b 25 41 4a 56 25 68 6a 61 60) |( 52 6e 6f 75 26 76 74 69 61 74 67 6b 26 65 67 68 68 69 72 26 64 63 26 74 73 68 26 6f 68 26 42 49 55 26 6b 69 62 63) |( 53 6f 6e 74 27 77 75 68 60 75 66 6a 27 64 66 69 69 68 73 27 65 62 27 75 72 69 27 6e 69 27 43 48 54 27 6a 68 63 62) |( 5c 60 61 7b 28 78 7a 67 6f 7a 69 65 28 6b 69 66 66 67 7c 28 6a 6d 28 7a 7d 66 28 61 66 28 4c 47 5b 28 65 67 6c 6d) |( 5d 61 60 7a 29 79 7b 66 6e 7b 68 64 29 6a 68 67 67 66 7d 29 6b 6c 29 7b 7c 67 29 60 67 29 4d 46 5a 29 64 66 6d 6c) |( 5e 62 63 79 2a 7a 78 65 6d 78 6b 67 2a 69 6b 64 64 65 7e 2a 68 6f 2a 78 7f 64 2a 63 64 2a 4e 45 59 2a 67 65 6e 6f) |( 5f 63 62 78 2b 7b 79 64 6c 79 6a 66 2b 68 6a 65 65 64 7f 2b 69 6e 2b 79 7e 65 2b 62 65 2b 4f 44 58 2b 66 64 6f 6e) |( 58 64 65 7f 2c 7c 7e 63 6b 7e 6d 61 2c 6f 6d 62 62 63 78 2c 6e 69 2c 7e 79 62 2c 65 62 2c 48 43 5f 2c 61 63 68 69) |( 59 65 64 7e 2d 7d 7f 62 6a 7f 6c 60 2d 6e 6c 63 63 62 79 2d 6f 68 2d 7f 78 63 2d 64 63 2d 49 42 5e 2d 60 62 69 68) |( 5a 66 67 7d 2e 7e 7c 61 69 7c 6f 63 2e 6d 6f 60 60 61 7a 2e 6c 6b 2e 7c 7b 60 2e 67 60 2e 4a 41 5d 2e 63 61 6a 6b) |( 5b 67 66 7c 2f 7f 7d 60 68 7d 6e 62 2f 6c 6e 61 61 60 7b 2f 6d 6a 2f 7d 7a 61 2f 66 61 2f 4b 40 5c 2f 62 60 6b 6a) |( 44 78 79 63 30 60 62 7f 77 62 71 7d 30 73 71 7e 7e 7f 64 30 72 75 30 62 65 7e 30 79 7e 30 54 5f 43 30 7d 7f 74 75) |( 45 79 78 62 31 61 63 7e 76 63 70 7c 31 72 70 7f 7f 7e 65 31 73 74 31 63 64 7f 31 78 7f 31 55 5e 42 31 7c 7e 75 74) |( 46 7a 7b 61 32 62 60 7d 75 60 73 7f 32 71 73 7c 7c 7d 66 32 70 77 32 60 67 7c 32 7b 7c 32 56 5d 41 32 7f 7d 76 77) |( 47 7b 7a 60 33 63 61 7c 74 61 72 7e 33 70 72 7d 7d 7c 67 33 71 76 33 61 66 7d 33 7a 7d 33 57 5c 40 33 7e 7c 77 76) |( 40 7c 7d 67 34 64 66 7b 73 66 75 79 34 77 75 7a 7a 7b 60 34 76 71 34 66 61 7a 34 7d 7a 34 50 5b 47 34 79 7b 70 71) |( 41 7d 7c 66 35 65 67 7a 72 67 74 78 35 76 74 7b 7b 7a 61 35 77 70 35 67 60 7b 35 7c 7b 35 51 5a 46 35 78 7a 71 70) |( 42 7e 7f 65 36 66 64 79 71 64 77 7b 36 75 77 78 78 79 62 36 74 73 36 64 63 78 36 7f 78 36 52 59 45 36 7b 79 72 73) |( 43 7f 7e 64 37 67 65 78 70 65 76 7a 37 74 76 79 79 78 63 37 75 72 37 65 62 79 37 7e 79 37 53 58 44 37 7a 78 73 72) |( 4c 70 71 6b 38 68 6a 77 7f 6a 79 75 38 7b 79 76 76 77 6c 38 7a 7d 38 6a 6d 76 38 71 76 38 5c 57 4b 38 75 77 7c 7d) |( 4d 71 70 6a 39 69 6b 76 7e 6b 78 74 39 7a 78 77 77 76 6d 39 7b 7c 39 6b 6c 77 39 70 77 39 5d 56 4a 39 74 76 7d 7c) |( 4e 72 73 69 3a 6a 68 75 7d 68 7b 77 3a 79 7b 74 74 75 6e 3a 78 7f 3a 68 6f 74 3a 73 74 3a 5e 55 49 3a 77 75 7e 7f) |( 4f 73 72 68 3b 6b 69 74 7c 69 7a 76 3b 78 7a 75 75 74 6f 3b 79 7e 3b 69 6e 75 3b 72 75 3b 5f 54 48 3b 76 74 7f 7e) |( 48 74 75 6f 3c 6c 6e 73 7b 6e 7d 71 3c 7f 7d 72 72 73 68 3c 7e 79 3c 6e 69 72 3c 75 72 3c 58 53 4f 3c 71 73 78 79) |( 49 75 74 6e 3d 6d 6f 72 7a 6f 7c 70 3d 7e 7c 73 73 72 69 3d 7f 78 3d 6f 68 73 3d 74 73 3d 59 52 4e 3d 70 72 79 78) |( 4a 76 77 6d 3e 6e 6c 71 79 6c 7f 73 3e 7d 7f 70 70 71 6a 3e 7c 7b 3e 6c 6b 70 3e 77 70 3e 5a 51 4d 3e 73 71 7a 7b) |( 4b 77 76 6c 3f 6f 6d 70 78 6d 7e 72 3f 7c 7e 71 71 70 6b 3f 7d 7a 3f 6d 6a 71 3f 76 71 3f 5b 50 4c 3f 72 70 7b 7a)  | ( 55 01 69 01 68 01 72 01 21 01 71 01 73 01 6e 01 66 01 73 01 60 01 6c 01 21 01 62 01 60 01 6f 01 6f 01 6e 01 75 01 21 01 63 01 64 01 21 01 73 01 74 01 6f 01 21 01 68 01 6f 01 21 01 45 01 4e 01 52 01 21 01 6c 01 6e 01 65 01 64 01) |( 56 02 6a 02 6b 02 71 02 22 02 72 02 70 02 6d 02 65 02 70 02 63 02 6f 02 22 02 61 02 63 02 6c 02 6c 02 6d 02 76 02 22 02 60 02 67 02 22 02 70 02 77 02 6c 02 22 02 6b 02 6c 02 22 02 46 02 4d 02 51 02 22 02 6f 02 6d 02 66 02 67 02) |( 57 03 6b 03 6a 03 70 03 23 03 73 03 71 03 6c 03 64 03 71 03 62 03 6e 03 23 03 60 03 62 03 6d 03 6d 03 6c 03 77 03 23 03 61 03 66 03 23 03 71 03 76 03 6d 03 23 03 6a 03 6d 03 23 03 47 03 4c 03 50 03 23 03 6e 03 6c 03 67 03 66 03) |( 50 04 6c 04 6d 04 77 04 24 04 74 04 76 04 6b 04 63 04 76 04 65 04 69 04 24 04 67 04 65 04 6a 04 6a 04 6b 04 70 04 24 04 66 04 61 04 24 04 76 04 71 04 6a 04 24 04 6d 04 6a 04 24 04 40 04 4b 04 57 04 24 04 69 04 6b 04 60 04 61 04) |( 51 05 6d 05 6c 05 76 05 25 05 75 05 77 05 6a 05 62 05 77 05 64 05 68 05 25 05 66 05 64 05 6b 05 6b 05 6a 05 71 05 25 05 67 05 60 05 25 05 77 05 70 05 6b 05 25 05 6c 05 6b 05 25 05 41 05 4a 05 56 05 25 05 68 05 6a 05 61 05 60 05) |( 52 06 6e 06 6f 06 75 06 26 06 76 06 74 06 69 06 61 06 74 06 67 06 6b 06 26 06 65 06 67 06 68 06 68 06 69 06 72 06 26 06 64 06 63 06 26 06 74 06 73 06 68 06 26 06 6f 06 68 06 26 06 42 06 49 06 55 06 26 06 6b 06 69 06 62 06 63 06) |( 53 07 6f 07 6e 07 74 07 27 07 77 07 75 07 68 07 60 07 75 07 66 07 6a 07 27 07 64 07 66 07 69 07 69 07 68 07 73 07 27 07 65 07 62 07 27 07 75 07 72 07 69 07 27 07 6e 07 69 07 27 07 43 07 48 07 54 07 27 07 6a 07 68 07 63 07 62 07) |( 5c 08 60 08 61 08 7b 08 28 08 78 08 7a 08 67 08 6f 08 7a 08 69 08 65 08 28 08 6b 08 69 08 66 08 66 08 67 08 7c 08 28 08 6a 08 6d 08 28 08 7a 08 7d 08 66 08 28 08 61 08 66 08 28 08 4c 08 47 08 5b 08 28 08 65 08 67 08 6c 08 6d 08) |( 5d 09 61 09 60 09 7a 09 29 09 79 09 7b 09 66 09 6e 09 7b 09 68 09 64 09 29 09 6a 09 68 09 67 09 67 09 66 09 7d 09 29 09 6b 09 6c 09 29 09 7b 09 7c 09 67 09 29 09 60 09 67 09 29 09 4d 09 46 09 5a 09 29 09 64 09 66 09 6d 09 6c 09) |( 5e 0a 62 0a 63 0a 79 0a 2a 0a 7a 0a 78 0a 65 0a 6d 0a 78 0a 6b 0a 67 0a 2a 0a 69 0a 6b 0a 64 0a 64 0a 65 0a 7e 0a 2a 0a 68 0a 6f 0a 2a 0a 78 0a 7f 0a 64 0a 2a 0a 63 0a 64 0a 2a 0a 4e 0a 45 0a 59 0a 2a 0a 67 0a 65 0a 6e 0a 6f 0a) |( 5f 0b 63 0b 62 0b 78 0b 2b 0b 7b 0b 79 0b 64 0b 6c 0b 79 0b 6a 0b 66 0b 2b 0b 68 0b 6a 0b 65 0b 65 0b 64 0b 7f 0b 2b 0b 69 0b 6e 0b 2b 0b 79 0b 7e 0b 65 0b 2b 0b 62 0b 65 0b 2b 0b 4f 0b 44 0b 58 0b 2b 0b 66 0b 64 0b 6f 0b 6e 0b) |( 58 0c 64 0c 65 0c 7f 0c 2c 0c 7c 0c 7e 0c 63 0c 6b 0c 7e 0c 6d 0c 61 0c 2c 0c 6f 0c 6d 0c 62 0c 62 0c 63 0c 78 0c 2c 0c 6e 0c 69 0c 2c 0c 7e 0c 79 0c 62 0c 2c 0c 65 0c 62 0c 2c 0c 48 0c 43 0c 5f 0c 2c 0c 61 0c 63 0c 68 0c 69 0c) |( 59 0d 65 0d 64 0d 7e 0d 2d 0d 7d 0d 7f 0d 62 0d 6a 0d 7f 0d 6c 0d 60 0d 2d 0d 6e 0d 6c 0d 63 0d 63 0d 62 0d 79 0d 2d 0d 6f 0d 68 0d 2d 0d 7f 0d 78 0d 63 0d 2d 0d 64 0d 63 0d 2d 0d 49 0d 42 0d 5e 0d 2d 0d 60 0d 62 0d 69 0d 68 0d) |( 5a 0e 66 0e 67 0e 7d 0e 2e 0e 7e 0e 7c 0e 61 0e 69 0e 7c 0e 6f 0e 63 0e 2e 0e 6d 0e 6f 0e 60 0e 60 0e 61 0e 7a 0e 2e 0e 6c 0e 6b 0e 2e 0e 7c 0e 7b 0e 60 0e 2e 0e 67 0e 60 0e 2e 0e 4a 0e 41 0e 5d 0e 2e 0e 63 0e 61 0e 6a 0e 6b 0e) |( 5b 0f 67 0f 66 0f 7c 0f 2f 0f 7f 0f 7d 0f 60 0f 68 0f 7d 0f 6e 0f 62 0f 2f 0f 6c 0f 6e 0f 61 0f 61 0f 60 0f 7b 0f 2f 0f 6d 0f 6a 0f 2f 0f 7d 0f 7a 0f 61 0f 2f 0f 66 0f 61 0f 2f 0f 4b 0f 40 0f 5c 0f 2f 0f 62 0f 60 0f 6b 0f 6a 0f) |( 44 10 78 10 79 10 63 10 30 10 60 10 62 10 7f 10 77 10 62 10 71 10 7d 10 30 10 73 10 71 10 7e 10 7e 10 7f 10 64 10 30 10 72 10 75 10 30 10 62 10 65 10 7e 10 30 10 79 10 7e 10 30 10 54 10 5f 10 43 10 30 10 7d 10 7f 10 74 10 75 10) |( 45 11 79 11 78 11 62 11 31 11 61 11 63 11 7e 11 76 11 63 11 70 11 7c 11 31 11 72 11 70 11 7f 11 7f 11 7e 11 65 11 31 11 73 11 74 11 31 11 63 11 64 11 7f 11 31 11 78 11 7f 11 31 11 55 11 5e 11 42 11 31 11 7c 11 7e 11 75 11 74 11) |( 46 12 7a 12 7b 12 61 12 32 12 62 12 60 12 7d 12 75 12 60 12 73 12 7f 12 32 12 71 12 73 12 7c 12 7c 12 7d 12 66 12 32 12 70 12 77 12 32 12 60 12 67 12 7c 12 32 12 7b 12 7c 12 32 12 56 12 5d 12 41 12 32 12 7f 12 7d 12 76 12 77 12) |( 47 13 7b 13 7a 13 60 13 33 13 63 13 61 13 7c 13 74 13 61 13 72 13 7e 13 33 13 70 13 72 13 7d 13 7d 13 7c 13 67 13 33 13 71 13 76 13 33 13 61 13 66 13 7d 13 33 13 7a 13 7d 13 33 13 57 13 5c 13 40 13 33 13 7e 13 7c 13 77 13 76 13) |( 40 14 7c 14 7d 14 67 14 34 14 64 14 66 14 7b 14 73 14 66 14 75 14 79 14 34 14 77 14 75 14 7a 14 7a 14 7b 14 60 14 34 14 76 14 71 14 34 14 66 14 61 14 7a 14 34 14 7d 14 7a 14 34 14 50 14 5b 14 47 14 34 14 79 14 7b 14 70 14 71 14) |( 41 15 7d 15 7c 15 66 15 35 15 65 15 67 15 7a 15 72 15 67 15 74 15 78 15 35 15 76 15 74 15 7b 15 7b 15 7a 15 61 15 35 15 77 15 70 15 35 15 67 15 60 15 7b 15 35 15 7c 15 7b 15 35 15 51 15 5a 15 46 15 35 15 78 15 7a 15 71 15 70 15) |( 42 16 7e 16 7f 16 65 16 36 16 66 16 64 16 79 16 71 16 64 16 77 16 7b 16 36 16 75 16 77 16 78 16 78 16 79 16 62 16 36 16 74 16 73 16 36 16 64 16 63 16 78 16 36 16 7f 16 78 16 36 16 52 16 59 16 45 16 36 16 7b 16 79 16 72 16 73 16) |( 43 17 7f 17 7e 17 64 17 37 17 67 17 65 17 78 17 70 17 65 17 76 17 7a 17 37 17 74 17 76 17 79 17 79 17 78 17 63 17 37 17 75 17 72 17 37 17 65 17 62 17 79 17 37 17 7e 17 79 17 37 17 53 17 58 17 44 17 37 17 7a 17 78 17 73 17 72 17) |( 4c 18 70 18 71 18 6b 18 38 18 68 18 6a 18 77 18 7f 18 6a 18 79 18 75 18 38 18 7b 18 79 18 76 18 76 18 77 18 6c 18 38 18 7a 18 7d 18 38 18 6a 18 6d 18 76 18 38 18 71 18 76 18 38 18 5c 18 57 18 4b 18 38 18 75 18 77 18 7c 18 7d 18) |( 4d 19 71 19 70 19 6a 19 39 19 69 19 6b 19 76 19 7e 19 6b 19 78 19 74 19 39 19 7a 19 78 19 77 19 77 19 76 19 6d 19 39 19 7b 19 7c 19 39 19 6b 19 6c 19 77 19 39 19 70 19 77 19 39 19 5d 19 56 19 4a 19 39 19 74 19 76 19 7d 19 7c 19) |( 4e 1a 72 1a 73 1a 69 1a 3a 1a 6a 1a 68 1a 75 1a 7d 1a 68 1a 7b 1a 77 1a 3a 1a 79 1a 7b 1a 74 1a 74 1a 75 1a 6e 1a 3a 1a 78 1a 7f 1a 3a 1a 68 1a 6f 1a 74 1a 3a 1a 73 1a 74 1a 3a 1a 5e 1a 55 1a 49 1a 3a 1a 77 1a 75 1a 7e 1a 7f 1a) |( 4f 1b 73 1b 72 1b 68 1b 3b 1b 6b 1b 69 1b 74 1b 7c 1b 69 1b 7a 1b 76 1b 3b 1b 78 1b 7a 1b 75 1b 75 1b 74 1b 6f 1b 3b 1b 79 1b 7e 1b 3b 1b 69 1b 6e 1b 75 1b 3b 1b 72 1b 75 1b 3b 1b 5f 1b 54 1b 48 1b 3b 1b 76 1b 74 1b 7f 1b 7e 1b) |( 48 1c 74 1c 75 1c 6f 1c 3c 1c 6c 1c 6e 1c 73 1c 7b 1c 6e 1c 7d 1c 71 1c 3c 1c 7f 1c 7d 1c 72 1c 72 1c 73 1c 68 1c 3c 1c 7e 1c 79 1c 3c 1c 6e 1c 69 1c 72 1c 3c 1c 75 1c 72 1c 3c 1c 58 1c 53 1c 4f 1c 3c 1c 71 1c 73 1c 78 1c 79 1c) |( 49 1d 75 1d 74 1d 6e 1d 3d 1d 6d 1d 6f 1d 72 1d 7a 1d 6f 1d 7c 1d 70 1d 3d 1d 7e 1d 7c 1d 73 1d 73 1d 72 1d 69 1d 3d 1d 7f 1d 78 1d 3d 1d 6f 1d 68 1d 73 1d 3d 1d 74 1d 73 1d 3d 1d 59 1d 52 1d 4e 1d 3d 1d 70 1d 72 1d 79 1d 78 1d) |( 4a 1e 76 1e 77 1e 6d 1e 3e 1e 6e 1e 6c 1e 71 1e 79 1e 6c 1e 7f 1e 73 1e 3e 1e 7d 1e 7f 1e 70 1e 70 1e 71 1e 6a 1e 3e 1e 7c 1e 7b 1e 3e 1e 6c 1e 6b 1e 70 1e 3e 1e 77 1e 70 1e 3e 1e 5a 1e 51 1e 4d 1e 3e 1e 73 1e 71 1e 7a 1e 7b 1e) |( 4b 1f 77 1f 76 1f 6c 1f 3f 1f 6f 1f 6d 1f 70 1f 78 1f 6d 1f 7e 1f 72 1f 3f 1f 7c 1f 7e 1f 71 1f 71 1f 70 1f 6b 1f 3f 1f 7d 1f 7a 1f 3f 1f 6d 1f 6a 1f 71 1f 3f 1f 76 1f 71 1f 3f 1f 5b 1f 50 1f 4c 1f 3f 1f 72 1f 70 1f 7b 1f 7a 1f) )}

	condition:
		any of them
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

