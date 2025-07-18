@echo off
REM Set path to your MySQL bin folder
set MYSQL_BIN="C:\Program Files\MySQL\MySQL Server 8.0\bin"

REM Set backup filename with timestamp
set BACKUP_FILE=backup_%date:~10,4%-%date:~4,2%-%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.sql

REM Perform the backup
%MYSQL_BIN%\mysqldump -u root -pCPT_2017 ticket_system > backups\%BACKUP_FILE%

echo Backup complete: backups\%BACKUP_FILE%
pause
