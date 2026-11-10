@echo off
setlocal
pushd "%~dp0.."
if not exist build mkdir build
if not exist native mkdir native
cl /nologo /std:c++17 /O2 /W4 /WX /MT /LD /EHsc /Fobuild\auto_save.obj source\auto_save.cpp /link /OUT:native\auto_save_race_replay.dll /IMPLIB:build\auto_save_race_replay.lib || exit /b 1
popd
