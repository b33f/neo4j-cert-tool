@echo off
rem Wrapper for neo4j-cert-tool on Windows.
rem
rem Locates the packaged jar relative to this script, picks a Java runtime, and passes every
rem argument through untouched.

setlocal

set "SCRIPT_DIR=%~dp0"
set "JAR=%SCRIPT_DIR%..\bin\neo4j-cert-tool.jar"

if not exist "%JAR%" (
    echo neo4j-cert-tool.jar not found at %JAR% 1>&2
    echo Build it first:  mvn package 1>&2
    exit /b 1
)

if defined JAVA_HOME (
    set "JAVA_CMD=%JAVA_HOME%\bin\java.exe"
) else (
    set "JAVA_CMD=java"
)

rem %* forwards all arguments; the tool's exit code is passed back to the caller.
"%JAVA_CMD%" -jar "%JAR%" %*
exit /b %ERRORLEVEL%
