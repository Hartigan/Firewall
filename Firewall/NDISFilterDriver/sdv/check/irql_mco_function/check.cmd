set PATH=C:\Program Files (x86)\Windows Kits\8.1\TOOLS\SDV\bin\engine;%PATH%
set PATH=C:\Program Files (x86)\Windows Kits\8.1\TOOLS\SDV\bin\engine\engineq;%PATH%
set PATH=C:\Program Files (x86)\Microsoft Visual Studio 12.0\\VC\bin\x86_amd64;C:\Program Files (x86)\Microsoft Visual Studio 12.0\\VC\bin;C:\Program Files (x86)\Microsoft Visual Studio 12.0\\common7\ide\;%PATH%
set PATH=%PATH%;C:\Program Files (x86)\Windows Kits\8.1\\bin\x64
set _CL_=
wlimit /b /r /c /w 3000 /u 3000 /m 1800 slam -no_slamcl  -rerun  -enableQ 1400 -Qlimit 3000 1800 -platform ndis -target X64 -sdvpath "D:\labs\myFirewall\Firewall\Firewall\NDISFilterDriver\sdv" -halt_labels -gate RunDispatchFunction -halt_labels -gate RunDispatchFunction -driver -arrays   -field_pa_version nocollapse -max_fields_nocollapse 5 -sourcedir "..\..\.."  -display_environment  irql_mco_function.fsm -tune_entry_points "D:\labs\myFirewall\Firewall\Firewall\NDISFilterDriver\SDV-map.h">wlimit.txt 2>wlimit.err
