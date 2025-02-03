rule turla_png_dropper : hardened
{
	meta:
		author = "Ben Humphrey"
		description = "Detects the PNG Dropper used by the Turla group"
		reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/"
		date = "2018/11/23"
		hash1 = "6ed939f59476fd31dc4d99e96136e928fbd88aec0d9c59846092c0e93a3c0e27"
		id = "459f17c8-0eae-5736-8c7c-286625dc158f"

	strings:
		$api0 = {47 64 69 70 6c 75 73 53 74 61 72 74 75 70}
		$api1 = {47 64 69 70 41 6c 6c 6f 63}
		$api2 = {47 64 69 70 43 72 65 61 74 65 42 69 74 6d 61 70 46 72 6f 6d 53 74 72 65 61 6d 49 43 4d}
		$api3 = {47 64 69 70 42 69 74 6d 61 70 4c 6f 63 6b 42 69 74 73}
		$api4 = {47 64 69 70 47 65 74 49 6d 61 67 65 57 69 64 74 68}
		$api5 = {47 64 69 70 47 65 74 49 6d 61 67 65 48 65 69 67 68 74}
		$api6 = {47 64 69 70 6c 75 73 53 68 75 74 64 6f 77 6e}
		$code32 = {
            8B 46 3C               // mov     eax, [esi+3Ch]
            B9 0B 01 00 00         // mov     ecx, 10Bh
            66 39 4C 30 18         // cmp     [eax+esi+18h], cx
            8B 44 30 28            // mov     eax, [eax+esi+28h]
            6A 00                  // push    0
            B9 AF BE AD DE         // mov     ecx, 0DEADBEAFh
            51                     // push    ecx
            51                     // push    ecx
            03 C6                  // add     eax, esi
            56                     // push    esi
            FF D0                  // call eax
        }
		$code64 = {
            48 63 43 3C            // movsxd rax, dword ptr [rbx+3Ch]
            B9 0B 01 00 00         // mov ecx, 10Bh
            BA AF BE AD DE         // mov edx, 0DEADBEAFh
            66 39 4C 18 18         // cmp [rax+rbx+18h], cx
            8B 44 18 28            // mov eax, [rax+rbx+28h]
            45 33 C9               // xor r9d, r9d
            44 8B C2               // mov r8d, edx
            48 8B CB               // mov rcx, rbx
            48 03 C3               // add rax, rbx
            FF D0                  // call rax
        }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and all of ( $api* ) and 1 of ( $code* )
}

import "pe"

rule turla_png_reg_enum_payload : hardened
{
	meta:
		author = "Ben Humphrey"
		description = "Payload that has most recently been dropped by the Turla PNG Dropper"
		reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/"
		date = "2018/11/23"
		hash1 = "fea27eb2e939e930c8617dcf64366d1649988f30555f6ee9cd09fe54e4bc22b3"
		id = "413bb315-3c01-56ab-92db-00342a11438a"

	strings:
		$crypt00 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 4b 00 65 00 79 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00}
		$crypt01 = {43 00 68 00 61 00 69 00 6e 00 69 00 6e 00 67 00 4d 00 6f 00 64 00 65 00 43 00 42 00 43 00}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and pe.imports ( "advapi32.dll" , "StartServiceCtrlDispatcherA" ) and pe.imports ( "advapi32.dll" , "RegEnumValueA" ) and pe.imports ( "advapi32.dll" , "RegEnumKeyExA" ) and pe.imports ( "ncrypt.dll" , "NCryptOpenStorageProvider" ) and pe.imports ( "ncrypt.dll" , "NCryptEnumKeys" ) and pe.imports ( "ncrypt.dll" , "NCryptOpenKey" ) and pe.imports ( "ncrypt.dll" , "NCryptDecrypt" ) and pe.imports ( "ncrypt.dll" , "BCryptGenerateSymmetricKey" ) and pe.imports ( "ncrypt.dll" , "BCryptGetProperty" ) and pe.imports ( "ncrypt.dll" , "BCryptDecrypt" ) and pe.imports ( "ncrypt.dll" , "BCryptEncrypt" ) and all of them
}

