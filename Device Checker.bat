:: powershell.exe -noprofile -ExecutionPolicy Unrestricted -command "&{start-process powershell -WindowStyle Maximized -ArgumentList '-ExecutionPolicy Unrestricted -noprofile -file ""%~dp0Device Checker.ps1""' -verb RunAs}

powershell -Command "Start-Process powershell -Verb RunAs -WindowStyle Maximized -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0Device Checker.ps1""'"
exit