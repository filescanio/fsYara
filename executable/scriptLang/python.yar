rule DetectSuspiciousPythonCode {
    meta:
        description = "Detects Python code patterns for importing setuptools and requests, requests.get calls, and certain exec/system uses"
        author = "Jan Miller, OPSWAT Inc."
        date = "2024-03-13"
        score = 50
        //7417987344440ddd9bef602d52e3aee1cbd1e529dcfd16bd87c11cea418b9900
    strings:
        $setuptools = "setuptools"
        $setup = "setup"
        $import_requests = "import requests"
        $requests_get_call = "requests.get("
        $exec_pattern = /\bexec\s*\(.+\)/
        $system_pattern = /\bsystem\s*\((\'|\")pip\s+install.+\)/
    condition:
        ($setuptools or $setup) and $import_requests and $requests_get_call and ($exec_pattern or $system_pattern)
}
