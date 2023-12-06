import "pe"
rule HellsGate_Dynamic_Syscalls   
   {   
   	meta:   
   		description = "Hell's Gate: Dynamic system call invocation "   
   		reference = "https://github.com/am0nsec/HellsGate/blob/master/HellsGate/hellsgate.asm"
         score = 75
      
   	strings:         
   		/*   
   			Hell's Gate / direct SYSCALLs for calling system routines   
      
   			4C 8B D1               mov     r10, rcx   
   			8B 05 36 2F 00 00      mov     eax, cs:dword_140005000   
   			0F 05                  syscall                
   			C3                     retn   
   		*/   
   		$hellDescent = { 4C 8B D1 8B 05 ?? ?? 00 00 0F 05 C3 }   
      
   		/*   
   			SYSCALL codes are stored in global variable   
      
   			C7 05 46 2F 00 00 00 00 00 00      mov     cs:dword_140005000, 0   
   			89 0D 40 2F 00 00                  mov     cs:dword_140005000, ecx   
   			C3                                 retn   
   		*/   
   		$hellsGate = {C7 05 ?? ?? 00 00 00 00 00 00 89 0D ?? ?? 00 00 C3}   
      
   	condition:
   		pe.is_pe and all of them
   }
