rule Worm_VBS_LoveLetter {
    meta:
        description = "Worm.VBS.LoveLetter"
        author = "opswat"
        ref = "https://github.com/onx/ILOVEYOU"
        score = 80

    strings:
        $signature1 = "barok -loveletter(vbe) <i hate go to school>"
        $signature2 = "LOVE-LETTER-FOR-YOU"

        // Copy itself into VBScript files MSKernel32.vbs, Win32DLL.vbs and LOVE-LETTER-FOR-YOU.TXT.vbs
        // Also in LOVE-LETTER-FOR-YOU.HTM
        $copy_file1 = "MSKernel32.vbs"
        $copy_file2 = "Win32DLL.vbs"
        $copy_file3 = "LOVE-LETTER-FOR-YOU.TXT.vbs"
        $copy_file4 = "LOVE-LETTER-FOR-YOU.HTM"

        // Download a malicious executable
        $download_explorer = "Internet Explorer\\Main\\StartPage"
        $download_startup = "Microsoft\\Windows\\CurrentVersion\\Run"
        $download_file = "WIN-BUGSFIX.exe"

        // IRC communication
        $irc1 = "script.ini"
        $irc2 = "mIRC Script"
        $irc3 = "http://www.mirc.com"

        // Email spreading
        $email_subject = {5375626a656374203d2022494c4f5645594f5522} // Subject = "ILOVEYOU"
        $email_outlook = {4372656174654f626a65637428224f75746c6f6f6b2e4170706c69636174696f6e2229} // CreateObject("Outlook.Application")
        $email_mapi = {4765744e616d65537061636528224d4150492229} // GetNameSpace("MAPI")
        $email_history = "Software\\Microsoft\\WAB"
        $email_contacts1 = "AddressLists"
        $email_contacts2 = "AddressEntries"

    condition:
        filesize < 25KB and (all of ($signature1, $signature2) or (9 of ($copy_file*, $download_*, $irc*, $email_*)))
}