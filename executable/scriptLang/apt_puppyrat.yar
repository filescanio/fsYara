// source: https://github.com/Neo23x0/signature-base/blob/99cc905c67522a1dea4e97cb15b13ff578118d6f/yara/apt_magichound.yar
rule APT_PupyRAT_PY {
   meta:
      description = "Detects Pupy RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations"
      date = "2017-02-17"
      hash1 = "8d89f53b0a6558d6bb9cdbc9f218ef699f3c87dd06bc03dd042290dedc18cb71"
      id = "cdd689e3-437e-514d-a058-fad80ce0639e"
   strings:
      // $x1 = "reflective_inject_dll" fullword ascii (covered with ReflectiveLoader yara rule)
      $x2 = "ImportError: pupy builtin module not found !" fullword ascii
      $x3 = "please start pupy from either it's exe stub or it's reflective DLLR;" fullword ascii
      $x4 = "[INJECT] inject_dll." fullword ascii
      $x5 = "import base64,zlib;exec zlib.decompress(base64.b64decode('eJzzcQz1c/ZwDbJVT87Py0tNLlHnAgA56wXS'))" fullword ascii

      $op1 = { 8b 42 0c 8b 78 14 89 5c 24 18 89 7c 24 14 3b fd } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and 1 of them ) or ( 2 of them )
}
