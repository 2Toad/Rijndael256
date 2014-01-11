@echo off
cls

echo Rijndael256
echo Copyright (C)2013 2Toad, LLC.
echo licensing@2toad.com
echo http://2toad.com/Project/Rijndael256/License

echo.
echo.
echo THIS BATCH FILE GENERATES RELEASE PACKAGES
echo.
echo.

echo Press CTRL+C to abort
pause
echo.
echo.

"%systemroot%\Microsoft.NET\Framework\v4.0.30319\MSBuild" Build.proj /t:Release
pause