@echo off
rem Launcher for neo4j-cert-tool on Windows.
rem
rem Finds a JDK and runs the packaged jar. Any arguments are passed straight through.

setlocal

set "SCRIPT_DIR=%~dp0"
set "JAR=%SCRIPT_DIR%..\target\neo4j-cert-tool.jar"

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

"%JAVA_CMD%" -jar "%JAR%" %*
exit /b %ERRORLEVEL%
