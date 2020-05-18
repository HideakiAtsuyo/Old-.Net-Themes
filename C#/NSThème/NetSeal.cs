using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Windows.Forms;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Net.Cache;
using System.Threading;
using System.Net.Sockets;
using System.Drawing;
using System.Globalization;

// Version: 2.1.1.1, Changed: 11/1/2016

namespace NetSeal
{

    internal sealed class Broker
    {

        #region " Events "

        /// <summary>
        /// Occurs when the user's license is suspended.
        /// </summary>
        public event LicenseSuspendedEventHandler LicenseSuspended;
        public delegate void LicenseSuspendedEventHandler(object sender, EventArgs e);

        /// <summary>
        /// Occurs when the user's license is authorized by the server.
        /// </summary>
        public event LicenseAuthorizedEventHandler LicenseAuthorized;
        public delegate void LicenseAuthorizedEventHandler(object sender, EventArgs e);

        /// <summary>
        /// Occurs when the user's license is reauthorized by the server.
        /// </summary>
        public event LicenseRefreshedEventHandler LicenseRefreshed;
        public delegate void LicenseRefreshedEventHandler(object sender, EventArgs e);

        #endregion

        #region " Properties "

        /// <summary>
        /// Gets the user's wide area network IPv4 address.
        /// </summary>
        public IPAddress IPAddress
        {
            get
            {
                EnsureInitialization();

                return (IPAddress)_AuthenticatorType.GetMethod("GetIPAddress").Invoke(_Authenticator, null);
            }
        }

        /// <summary>
        /// Gets the user's sign-in name.
        /// </summary>
        public string UserName
        {
            get
            {
                EnsureInitialization();

                return (string)_AuthenticatorType.GetMethod("GetUserName").Invoke(_Authenticator, null);
            }
        }

        /// <summary>
        /// Gets the expiration date of the user's license, when <see cref="LicenseExpires"/> is True. 
        /// </summary>
        public System.DateTime ExpirationDate
        {
            get
            {
                EnsureInitialization();

                return (System.DateTime)_AuthenticatorType.GetMethod("GetExpirationDate").Invoke(_Authenticator, null);
            }
        }

        /// <summary>
        /// Gets the time remaining on the user's license, when <see cref="LicenseExpires"/> is True. 
        /// </summary>
        public TimeSpan TimeRemaining
        {
            get
            {
                EnsureInitialization();

                return (TimeSpan)_AuthenticatorType.GetMethod("GetTimeRemaining").Invoke(_Authenticator, null);
            }
        }

        /// <summary>
        /// Gets the license type associated with the user's license.
        /// </summary>
        public LicenseType LicenseType
        {
            get
            {
                EnsureInitialization();

                return (LicenseType)_AuthenticatorType.GetMethod("GetLicenseType").Invoke(_Authenticator, null);
            }
        }

        /// <summary>
        /// Gets a value indicating whether the user's license will expire.
        /// </summary>
        public bool LicenseExpires
        {
            get
            {
                EnsureInitialization();

                return (bool)_AuthenticatorType.GetMethod("GetLicenseExpires").Invoke(_Authenticator, null);
            }
        }

        /// <summary>
        /// Gets a unique identifier for the machine. This value is not static.
        /// </summary>
        public string MachineId
        {
            get
            {
                EnsureInitialization();

                return (string)_AuthenticatorType.GetMethod("GetMachineId").Invoke(_Authenticator, null);
            }
        }

        #endregion

        #region " Commands "

        /// <summary>
        /// Gets a token representing the key returned by <see cref="GetPrivateKey"/> which can be decoded with the PrivateKey web API.
        /// </summary>
        public string GetPublicToken()
        {
            EnsureInitialization();

            return (string)_AuthenticatorType.GetMethod("GetPublicToken").Invoke(_Authenticator, null);
        }

        /// <summary>
        /// Gets a secret key that can be used for encryption.
        /// </summary>
        public byte[] GetPrivateKey()
        {
            EnsureInitialization();

            return (byte[])_AuthenticatorType.GetMethod("GetPrivateKey").Invoke(_Authenticator, null);
        }

        /// <summary>
        /// Gets the number of users currently signed in and using the program.
        /// </summary>
        public int GetUsersOnline()
        {
            EnsureInitialization();

            return (int)_AuthenticatorType.GetMethod("GetUsersOnline").Invoke(_Authenticator, null);
        }

        /// <summary>
        /// Gets a value indicating whether updates are available.
        /// </summary>
        public bool GetUpdatesAvailable()
        {
            EnsureInitialization();

            return (bool)_AuthenticatorType.GetMethod("GetUpdatesAvailable").Invoke(_Authenticator, null);
        }

        /// <summary>
        /// Gets blog posts submitted by the application developer.
        /// </summary>
        public BlogPost[] GetBlogPosts()
        {
            EnsureInitialization();

            List<BlogPost> Posts = new List<BlogPost>();
            object[] Values = (object[])_AuthenticatorType.GetMethod("GetBlogPosts").Invoke(_Authenticator, null);

            for (int I = 0; I <= Values.Length - 1; I += 4)
            {
                int Id = (int)Values[I];
                string Title = (string)Values[I + 1];
                int TimesRead = (int)Values[I + 2];
                System.DateTime DatePosted = (System.DateTime)Values[I + 3];

                BlogPost Post = new BlogPost(Id, Title, TimesRead, DatePosted, new GetPostBodyDelegate(GetPostBody));
                Posts.Add(Post);
            }

            return Posts.ToArray();
        }

        /// <summary>
        /// Gets settings defined by the application developer.
        /// </summary>
        public string GetSetting(string name)
        {
            EnsureInitialization();

            return (string)_AuthenticatorType.GetMethod("GetSetting").Invoke(_Authenticator, new object[] { name });
        }

        /// <summary>
        /// Downloads and installs updates if they are available.
        /// </summary>
        public void InstallUpdates()
        {
            EnsureInitialization();

            _AuthenticatorType.GetMethod("InstallUpdates").Invoke(_Authenticator, null);
        }

        /// <summary>
        /// Suspends the currently signed in user's license.
        /// </summary>
        public void SuspendUser(string reason)
        {
            EnsureInitialization();

            _AuthenticatorType.GetMethod("SuspendUser").Invoke(_Authenticator, new object[] { reason });
        }

        #endregion

        #region " Members "


        private Version _Version;

        private Type _LzmaLibType;
        private object _Authenticator;

        private Type _AuthenticatorType;
        private HttpClient _HttpClient;
        private DnsClient _DnsClient;

        private StrongNameVerifierLite _StrongNameVerifier;
        private string _PreferredMetadataEndPoint;

        private string _AlternateMetadataEndPoint;
        private ICryptoTransform _ComponentAesEncryptor;

        private ICryptoTransform _ComponentAesDecryptor;
        private byte[] _ComponentKey;

        private byte[] _AuthenticatorKey;
        private string _ServerEndPoint;

        private string _ComponentEndPoint;
        private string _LzmaLibHash;

        private string _AuthenticatorHash;
        private byte[] _LzmaLibData;

        private byte[] _AuthenticatorData;

        private string _ProductDirectory;
        #endregion

        #region " Delegates "

        private delegate void CallbackDelegate();
        private delegate string GetPostBodyDelegate(int postId);

        #endregion

        #region " Event Handling "

        private void HttpClient_WebRequestResolveHost(object sender, HttpClient.WebRequestResolveHostEventArgs e)
        {
            try
            {
                IPAddress[] AddressList = null;

                lock (_DnsClient)
                {
                    AddressList = _DnsClient.Resolve(e.HostName);
                }

                if (AddressList.Length == 0)
                {
                    return;
                }

                e.Address = AddressList[0];
            }
            catch (Exception ex)
            {
                HandleException(ex);
            }
        }

        #endregion

        #region " Constructor "

        public Broker()
        {
            _Version = new Version(2, 1, 1, 1);

            _PreferredMetadataEndPoint = "http://seal.nimoru.com/Base/checksumSE.php";
            _AlternateMetadataEndPoint = "https://s3-us-west-2.amazonaws.com/netseal/checksumSE.txt";

            _ComponentKey = new byte[] { 65, 118, 65, 114, 101, 79, 118, 101, 114, 122, 101, 97, 108, 111, 117, 115 };
            _AuthenticatorKey = new byte[] { 6, 2, 0, 0, 0, 34, 0, 0, 68, 83, 83, 49, 0, 4, 0, 0, 165, 101, 186, 183, 89, 49, 161, 242, 152, 217, 52, 227, 36, 114, 221, 81, 163, 208, 24, 95, 234, 1, 136, 6, 193, 171, 215, 57, 56, 216, 186, 221, 159, 6, 11, 126, 249, 251, 48, 16, 34, 98, 128, 135, 217, 192, 244, 236, 207, 199, 184, 206, 141, 91, 85, 170, 37, 5, 69, 218, 137, 176, 31, 148, 182, 215, 92, 31, 188, 16, 174, 181, 79, 118, 71, 21, 229, 118, 103, 239, 119, 78, 165, 241, 228, 42, 154, 154, 115, 181, 130, 43, 93, 220, 102, 91, 64, 81, 150, 139, 1, 40, 243, 57, 154, 206, 152, 93, 153, 232, 48, 171, 30, 2, 138, 153, 232, 8, 243, 107, 197, 61, 64, 34, 76, 145, 33, 210, 71, 227, 182, 220, 74, 6, 143, 213, 126, 239, 28, 36, 10, 134, 7, 146, 81, 109, 44, 156, 196, 68, 30, 178, 252, 53, 181, 4, 32, 135, 132, 182, 229, 206, 145, 115, 250, 104, 109, 212, 32, 250, 196, 8, 182, 64, 19, 88, 238, 246, 92, 89, 214, 234, 163, 230, 75, 79, 140, 187, 179, 15, 35, 83, 173, 101, 137, 128, 110, 100, 176, 63, 183, 238, 138, 30, 26, 8, 193, 159, 141, 32, 74, 236, 8, 117, 185, 68, 63, 101, 159, 149, 105, 48, 46, 186, 192, 16, 156, 99, 159, 120, 101, 50, 12, 106, 114, 46, 190, 106, 112, 225, 228, 26, 81, 118, 79, 160, 202, 32, 127, 111, 96, 38, 2, 82, 162, 86, 131, 131, 152, 143, 213, 112, 234, 204, 228, 207, 187, 212, 93, 176, 119, 183, 71, 86, 90, 54, 9, 107, 47, 78, 115, 161, 51, 61, 225, 153, 37, 228, 164, 254, 108, 240, 20, 11, 223, 100, 26, 177, 3, 152, 216, 169, 123, 171, 99, 240, 92, 40, 57, 51, 77, 105, 54, 142, 189, 102, 101, 93, 59, 64, 125, 172, 106, 25, 94, 59, 159, 18, 159, 105, 184, 49, 18, 93, 60, 159, 71, 55, 60, 18, 68, 141, 70, 115, 39, 135, 33, 193, 13, 132, 199, 96, 57, 185, 128, 96, 70, 233, 28, 152, 169, 145, 153, 220, 8, 166, 17, 234, 208, 140, 29, 163, 20, 181, 251, 161, 210, 193, 124, 96, 213, 221, 196, 16, 10, 49, 39, 190, 81, 213, 228, 151, 23, 231, 23, 57, 224, 187, 119, 245, 54, 81, 141, 45, 171, 0, 0, 0, 203, 211, 139, 62, 110, 51, 58, 65, 64, 134, 29, 53, 198, 216, 158, 178, 112, 28, 230, 228 };
        }

        #endregion

        #region " Initialization "

        /// <summary>
        /// Initializes the authenticator and shows the authentication dialog.
        /// </summary>
        public void Initialize(string productId)
        {
            Initialize(productId, new BrokerSettings());
        }

        /// <summary>
        /// Initializes the authenticator and shows the authentication dialog.
        /// </summary>
        public void Initialize(string productId, BrokerSettings settings)
        {
            try
            {
                if (_Authenticator != null)
                {
                    throw new Exception("Loader has already been initialized.");
                }

                if (settings == null)
                {
                    throw new ArgumentNullException("settings");
                }

                ThreadCulture Culture = NormalizeCulture();

                if (settings.VerifyRuntimeIntegrity)
                {
                    _StrongNameVerifier = new StrongNameVerifierLite();
                    CheckFrameworkStrongNames();
                }

                InitializeWebHandling();
                InitializeComponentTransform();

                _ProductDirectory = GetProductDirectory();

                string[] Metadata = GetMetadata();
                ParseMetadata(Metadata);

                if (!Directory.Exists(_ProductDirectory))
                {
                    Directory.CreateDirectory(_ProductDirectory);
                }

                InitializeLzmaLib();
                InitializeAuthenticator();

                VerifyAuthenticator();

                _AuthenticatorType = System.Reflection.Assembly.Load(_AuthenticatorData).GetType("Controller");
                _Authenticator = Activator.CreateInstance(_AuthenticatorType);

                MethodInfo UpdateMethod = _AuthenticatorType.GetMethod("UpdateValue");

                UpdateMethod.Invoke(_Authenticator, new object[] { "ProductId", productId });
                UpdateMethod.Invoke(_Authenticator, new object[] { "CatchUnhandledExceptions", settings.CatchUnhandledExceptions });
                UpdateMethod.Invoke(_Authenticator, new object[] { "DeferAutomaticUpdates", settings.DeferAutomaticUpdates });
                UpdateMethod.Invoke(_Authenticator, new object[] { "SilentAuthentication", settings.SilentAuthentication });
                UpdateMethod.Invoke(_Authenticator, new object[] { "DialogTheme", Convert.ToInt32(settings.DialogTheme) });
                UpdateMethod.Invoke(_Authenticator, new object[] { "LoaderVersion", _Version });
                UpdateMethod.Invoke(_Authenticator, new object[] { "ProductVersion", new Version(Application.ProductVersion) });
                UpdateMethod.Invoke(_Authenticator, new object[] { "Metadata", Metadata });
                UpdateMethod.Invoke(_Authenticator, new object[] { "AuthorizedCallback", new CallbackDelegate(AuthorizedCallback) });
                UpdateMethod.Invoke(_Authenticator, new object[] { "RefreshedCallback", new CallbackDelegate(RefreshedCallback) });
                UpdateMethod.Invoke(_Authenticator, new object[] { "SuspendedCallback", new CallbackDelegate(SuspendedCallback) });

                MethodInfo InitializeMethod = _AuthenticatorType.GetMethod("Initialize");
                InitializeMethod.Invoke(_Authenticator, null);

                DisposeMembers();

                RestoreCulture(Culture);
            }
            catch (Exception ex)
            {
                HandleException(ex);
            }
        }

        private void InitializeWebHandling()
        {
            _DnsClient = new DnsClient();
            _HttpClient = new HttpClient();

            _HttpClient.RequestThrottleTime = 100;
            _HttpClient.MaxConcurrentRequests = 1;

            _HttpClient.WebRequestResolveHost += HttpClient_WebRequestResolveHost;
        }

        private void InitializeComponentTransform()
        {
            RijndaelManaged Aes = new RijndaelManaged();
            Aes.BlockSize = 128;
            Aes.KeySize = 128;
            Aes.Padding = PaddingMode.PKCS7;
            Aes.Mode = CipherMode.CBC;

            Aes.Key = _ComponentKey;
            Aes.IV = Aes.Key;

            _ComponentAesEncryptor = Aes.CreateEncryptor();
            _ComponentAesDecryptor = Aes.CreateDecryptor();
        }

        #endregion

        #region " Delegate Handling "

        private void AuthorizedCallback()
        {
            if (LicenseAuthorized != null)
            {
                LicenseAuthorized(this, EventArgs.Empty);
            }
        }

        private void RefreshedCallback()
        {
            if (LicenseRefreshed != null)
            {
                LicenseRefreshed(this, EventArgs.Empty);
            }
        }

        private void SuspendedCallback()
        {
            if (LicenseSuspended != null)
            {
                LicenseSuspended(this, EventArgs.Empty);
            }
        }

        private string GetPostBody(int postId)
        {
            return (string)_AuthenticatorType.GetMethod("GetPostBody").Invoke(_Authenticator, new object[] { postId });
        }

        #endregion

        #region " Exception Handling "

        private void HandleException(Exception ex)
        {
            string StackTrace = ExceptionToString(ex);

            StringBuilder Builder = new StringBuilder();
            Builder.AppendFormat("[Loader: {0}]", _Version);
            Builder.AppendLine();
            Builder.AppendLine();
            Builder.Append(StackTrace);

            ExceptionForm ExceptionForm = new ExceptionForm(Builder.ToString());
            ExceptionForm.ShowDialog();

            Environment.Exit(0);
        }

        private string ExceptionToString(Exception ex)
        {
            StringBuilder Builder = new StringBuilder();

            Builder.AppendLine(ex.Message);
            Builder.AppendLine();
            Builder.AppendLine(ex.GetType().FullName);
            Builder.AppendLine(ex.StackTrace);

            if (ex.InnerException != null)
            {
                Builder.AppendLine();
                Builder.AppendLine(ExceptionToString(ex.InnerException));
            }

            return Builder.ToString();
        }

        private void EnsureInitialization()
        {
            if (_Authenticator == null)
            {
                throw new Exception("Loader has not been initialized.");
            }
        }

        #endregion

        #region " Verification "

        private void CheckFrameworkStrongNames()
        {
            string Base = RuntimeEnvironment.GetRuntimeDirectory();
            byte[] EcmaToken = new byte[] { 183, 122, 92, 86, 25, 52, 224, 137 }; //b77a5c561934e089
            byte[] FinalToken = new byte[] { 176, 63, 95, 127, 17, 213, 10, 58 }; //b03f5f7f11d50a3a

            CheckStrongName(Path.Combine(Base, "mscorlib.dll"), EcmaToken);
            CheckStrongName(Path.Combine(Base, "System.dll"), EcmaToken);
            CheckStrongName(Path.Combine(Base, "System.Security.dll"), FinalToken);
        }

        private void CheckStrongName(string fileName, byte[] token)
        {
            string AssemblyName = Path.GetFileName(fileName);

            if (!_StrongNameVerifier.VerifyStrongName(fileName, token))
            {
                throw new Exception(string.Format("Could not verify strong name of file or assembly '{0}'.", AssemblyName));
            }
        }

        private void VerifyAuthenticator()
        {
            byte[] Signature = new byte[40];
            byte[] ImageData = new byte[_AuthenticatorData.Length - 42];

            Buffer.BlockCopy(_AuthenticatorData, 2, Signature, 0, Signature.Length);
            Buffer.BlockCopy(_AuthenticatorData, 42, ImageData, 0, ImageData.Length);

            DSACryptoServiceProvider DsaProvider = new DSACryptoServiceProvider();
            DsaProvider.ImportCspBlob(_AuthenticatorKey);

            if (!DsaProvider.VerifyData(ImageData, Signature))
            {
                throw new Exception("Could not verify signature of authenticator.");
            }
        }

        #endregion

        #region " Metadata "

        private string[] GetMetadata()
        {
            try
            {
                byte[] Data = DownloadData(_PreferredMetadataEndPoint);
                return Encoding.UTF8.GetString(Data).Split(char.MinValue);
            }
            catch
            {
                return GetMetadataFallback();
            }
        }

        private string[] GetMetadataFallback()
        {
            try
            {
                byte[] Data = DownloadData(_AlternateMetadataEndPoint);
                return Encoding.UTF8.GetString(Data).Split('|');
            }
            catch (Exception ex)
            {
                HandleException(ex);
            }

            return null;
        }

        private void ParseMetadata(string[] metadata)
        {
            _ComponentEndPoint = metadata[0];
            _LzmaLibHash = metadata[1];
            _AuthenticatorHash = metadata[3];
            _ServerEndPoint = metadata[5];
        }

        #endregion

        #region " Hashing "

        private string Md5HashData(byte[] data)
        {
            MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider();
            return ByteArrayToString(MD5.ComputeHash(data));
        }

        private string ByteArrayToString(byte[] data)
        {
            return BitConverter.ToString(data).ToLower().Replace("-", string.Empty);
        }

        #endregion

        #region " LzmaLib "

        private void InitializeLzmaLib()
        {
            string LzmaLibFileName = GetLzmaLibFileName();

            if (File.Exists(LzmaLibFileName))
            {
                _LzmaLibData = LoadComponentData(LzmaLibFileName);

                if (!_LzmaLibHash.Equals(Md5HashData(_LzmaLibData)))
                {
                    _LzmaLibData = InstallLzmaLib(LzmaLibFileName);
                }
            }
            else
            {
                _LzmaLibData = InstallLzmaLib(LzmaLibFileName);
            }
        }

        private byte[] InstallLzmaLib(string fileName)
        {
            string Url = GetComponentEndPoint(_LzmaLibHash);
            byte[] Data = DeflateDecompress(DownloadData(Url));

            SaveComponentData(fileName, Data);

            return Data;
        }

        private string GetLzmaLibFileName()
        {
            return Path.Combine(_ProductDirectory, "LzmaLib.bin");
        }

        #endregion

        #region " Authenticator "

        private void InitializeAuthenticator()
        {
            string AuthenticatorFileName = GetAuthenticatorFileName();

            if (File.Exists(AuthenticatorFileName))
            {
                _AuthenticatorData = LoadComponentData(AuthenticatorFileName);

                if (!_AuthenticatorHash.Equals(Md5HashData(_AuthenticatorData)))
                {
                    _AuthenticatorData = InstallAuthenticator(AuthenticatorFileName);
                }
            }
            else
            {
                _AuthenticatorData = InstallAuthenticator(AuthenticatorFileName);
            }
        }

        private byte[] InstallAuthenticator(string fileName)
        {
            string Url = GetComponentEndPoint(_AuthenticatorHash);
            byte[] Data = LzmaDecompress(DownloadData(Url));

            SaveComponentData(fileName, Data);

            return Data;
        }

        private string GetAuthenticatorFileName()
        {
            return Path.Combine(_ProductDirectory, "License.bin");
        }

        #endregion

        #region " Component Helpers "

        private string GetComponentEndPoint(string hash)
        {
            return Path.Combine(_ComponentEndPoint, hash) + ".co";
        }

        private byte[] LoadComponentData(string fileName)
        {
            byte[] Data = File.ReadAllBytes(fileName);

            return _ComponentAesDecryptor.TransformFinalBlock(Data, 0, Data.Length);
        }

        private void SaveComponentData(string fileName, byte[] data)
        {
            byte[] ComponentData = _ComponentAesEncryptor.TransformFinalBlock(data, 0, data.Length);

            File.WriteAllBytes(fileName, ComponentData);
        }

        #endregion

        #region " Decompression "

        private byte[] DeflateDecompress(byte[] data)
        {
            int Length = BitConverter.ToInt32(data, 0);

            byte[] Buffer = new byte[Length];
            MemoryStream Stream = new MemoryStream(data, 4, data.Length - 4);

            DeflateStream Deflate = new DeflateStream(Stream, CompressionMode.Decompress, false);
            Deflate.Read(Buffer, 0, Buffer.Length);

            Deflate.Close();
            Stream.Close();

            return Buffer;
        }

        private byte[] LzmaDecompress(byte[] data)
        {
            if (_LzmaLibType == null)
            {
                _LzmaLibType = System.Reflection.Assembly.Load(_LzmaLibData).GetType("H");
            }

            return (byte[])_LzmaLibType.GetMethod("Decompress").Invoke(null, new object[] { data });
        }

        #endregion

        #region " Helpers "

        private byte[] DownloadData(string url)
        {
            HttpClient.RequestOptions Options = new HttpClient.RequestOptions();
            Options.Timeout = 60000;
            Options.RetryCount = 3;
            Options.Proxy = null;
            Options.Method = "GET";

            return _HttpClient.UploadValues(url, null, Options);
        }

        private string GetProductDirectory()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Net Seal");
        }

        private ThreadCulture NormalizeCulture()
        {
            Thread Thread = System.Threading.Thread.CurrentThread;
            ThreadCulture Culture = new ThreadCulture(Thread.CurrentCulture, Thread.CurrentUICulture);

            Thread.CurrentCulture = CultureInfo.InvariantCulture;
            Thread.CurrentUICulture = CultureInfo.InvariantCulture;

            return Culture;
        }

        private void RestoreCulture(ThreadCulture threadCulture)
        {
            Thread Thread = System.Threading.Thread.CurrentThread;

            Thread.CurrentCulture = threadCulture.Culture;
            Thread.CurrentUICulture = threadCulture.UICulture;
        }

        #endregion

        #region " Disposal "

        private void DisposeMembers()
        {
            _LzmaLibData = null;
            _AuthenticatorData = null;
            _ComponentKey = null;
            _AuthenticatorKey = null;

            _ComponentEndPoint = null;
            _ServerEndPoint = null;
            _AuthenticatorHash = null;
            _LzmaLibHash = null;
            _PreferredMetadataEndPoint = null;
            _AlternateMetadataEndPoint = null;

            _LzmaLibType = null;

            _HttpClient = null;
            _DnsClient = null;
            _StrongNameVerifier = null;

            _ComponentAesDecryptor = null;
            _ComponentAesEncryptor = null;
        }

        #endregion

        #region " Private Types "

        private sealed class ThreadCulture
        {

            public CultureInfo Culture
            {
                get { return _Culture; }
            }

            public CultureInfo UICulture
            {
                get { return _UICulture; }
            }

            private CultureInfo _Culture;

            private CultureInfo _UICulture;
            public ThreadCulture(CultureInfo culture, CultureInfo uiCulture)
            {
                _Culture = culture;
                _UICulture = uiCulture;
            }

        }

        private sealed class StrongNameVerifierLite
        {

            private string _RuntimeVersion;
            private IStrongName _StrongName;

            private bool _UsingComInterfaces;
            public StrongNameVerifierLite()
            {
                _RuntimeVersion = RuntimeEnvironment.GetSystemVersion();

                if (Int32.Parse(_RuntimeVersion[1].ToString()) >= 4)
                {
                    _UsingComInterfaces = true;
                    InitializeComInterfaces();
                }
            }

            private void InitializeComInterfaces()
            {
                Guid CID_META_HOST = new Guid("9280188D-0E8E-4867-B30C-7FA83884E8DE");
                Guid CID_STRONG_NAME = new Guid("B79B0ACD-F5CD-409B-B5A5-A16244610B92");

                IMeta Meta = (IMeta)CLRCreateInstance(CID_META_HOST, typeof(IMeta).GUID);
                IRuntime Runtime = (IRuntime)Meta.GetRuntime(_RuntimeVersion, typeof(IRuntime).GUID);

                _StrongName = (IStrongName)Runtime.GetInterface(CID_STRONG_NAME, typeof(IStrongName).GUID);
            }

            public bool VerifyStrongName(string assemblyPath, byte[] publicToken)
            {
                return VerifyStrongName(assemblyPath, publicToken, false);
            }

            public bool VerifyStrongName(string assemblyPath, byte[] publicToken, bool ignoreToken)
            {
                IntPtr Token = default(IntPtr);
                int TokenLength = 0;
                bool Genuine = false;

                if (_UsingComInterfaces)
                {
                    if (!(_StrongName.StrongNameSignatureVerificationEx(assemblyPath, true, ref Genuine) == 0 && Genuine))
                    {
                        return false;
                    }

                    if (!ignoreToken && !(_StrongName.StrongNameTokenFromAssembly(assemblyPath, ref Token, ref TokenLength) == 0))
                    {
                        return false;
                    }
                }
                else
                {
                    if (!(StrongNameSignatureVerificationEx(assemblyPath, true, ref Genuine) && Genuine))
                    {
                        return false;
                    }

                    if (!ignoreToken && !StrongNameTokenFromAssembly(assemblyPath, ref Token, ref TokenLength))
                    {
                        return false;
                    }
                }

                if (!ignoreToken)
                {
                    byte[] TokenData = new byte[TokenLength];
                    Marshal.Copy(Token, TokenData, 0, TokenLength);

                    if (_UsingComInterfaces)
                    {
                        _StrongName.StrongNameFreeBuffer(Token);
                    }
                    else
                    {
                        StrongNameFreeBuffer(Token);
                    }

                    if (!(TokenData.Length == publicToken.Length))
                    {
                        return false;
                    }

                    for (int I = 0; I <= TokenData.Length - 1; I++)
                    {
                        if (!(TokenData[I] == publicToken[I]))
                            return false;
                    }
                }

                return true;
            }

            [DllImport("mscoree.dll", EntryPoint = "StrongNameFreeBuffer")]
            private static extern void StrongNameFreeBuffer(IntPtr token);

            [DllImport("mscoree.dll", EntryPoint = "StrongNameSignatureVerificationEx", CharSet = CharSet.Unicode)]
            private static extern bool StrongNameSignatureVerificationEx(string fileName, bool force, ref bool genuine);

            [DllImport("mscoree.dll", EntryPoint = "StrongNameTokenFromAssembly", CharSet = CharSet.Unicode)]
            private static extern bool StrongNameTokenFromAssembly(string fileName, ref IntPtr token, ref int tokenLength);

            [DllImport("mscoree.dll", PreserveSig = false, EntryPoint = "CLRCreateInstance")]
            [return: MarshalAs(UnmanagedType.Interface)]
            private static extern object CLRCreateInstance([MarshalAs(UnmanagedType.LPStruct)] Guid cid, [MarshalAs(UnmanagedType.LPStruct)] Guid iid);

            [InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("D332DB9E-B9B3-4125-8207-A14884F53216")]
            private interface IMeta
            {
                [return: MarshalAs(UnmanagedType.Interface)]
                object GetRuntime(string version, [MarshalAs(UnmanagedType.LPStruct)] Guid iid);
            }

            [InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("BD39D1D2-BA2F-486A-89B0-B4B0CB466891")]
            private interface IRuntime
            {
                void Reserved1();
                void Reserved2();
                void Reserved3();
                void Reserved4();
                void Reserved5();
                void Reserved6();
                [return: MarshalAs(UnmanagedType.Interface)]
                object GetInterface([MarshalAs(UnmanagedType.LPStruct)] Guid cid, [MarshalAs(UnmanagedType.LPStruct)] Guid iid);
            }

            [InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("9FD93CCF-3280-4391-B3A9-96E1CDE77C8D")]
            private interface IStrongName
            {
                void Reserved1();
                void Reserved2();
                void Reserved3();
                void Reserved4();
                void Reserved5();
                void Reserved6();
                void Reserved7();
                int StrongNameFreeBuffer(IntPtr token);
                void Reserved8();
                void Reserved9();
                void Reserved10();
                void Reserved11();
                void Reserved12();
                void Reserved13();
                void Reserved14();
                void Reserved15();
                void Reserved16();
                void Reserved17();
                void Reserved18();
                void Reserved19();
                int StrongNameSignatureVerificationEx(string filePath, bool force, ref bool genuine);
                void Reserved20();
                int StrongNameTokenFromAssembly(string filePath, ref IntPtr token, ref int tokenLength);
            }

        }

        private sealed class ExceptionForm : Form
        {

            public ExceptionForm(string stackTrace)
            {
                SuspendLayout();

                PictureBox PictureBox = new PictureBox();
                PictureBox.Location = new Point(12, 9);
                PictureBox.Size = new Size(32, 32);
                PictureBox.TabStop = false;
                PictureBox.Image = SystemIcons.Error.ToBitmap();

                Label Label = new Label();
                Label.Anchor = (AnchorStyles)13;
                Label.AutoEllipsis = true;
                Label.Font = new Font("Verdana", 8.25f);
                Label.Location = new Point(50, 9);
                Label.Size = new Size(367, 32);
                Label.Text = "The application has encountered an unexpected exception and must terminate.";
                Label.TextAlign = ContentAlignment.MiddleLeft;

                TextBox TextBox = new TextBox();
                TextBox.Anchor = (AnchorStyles)15;
                TextBox.BackColor = SystemColors.Window;
                TextBox.Font = new Font("Verdana", 8.25f);
                TextBox.Location = new Point(12, 47);
                TextBox.Multiline = true;
                TextBox.ReadOnly = true;
                TextBox.ScrollBars = ScrollBars.Vertical;
                TextBox.Size = new Size(405, 183);
                TextBox.Text = stackTrace;

                Button Button = new Button();
                Button.Anchor = (AnchorStyles)10;
                Button.DialogResult = (DialogResult)2;
                Button.Font = new Font("Verdana", 8.25f);
                Button.Location = new Point(312, 236);
                Button.Size = new Size(105, 26);
                Button.TabIndex = 0;
                Button.Text = "Close";
                Button.UseVisualStyleBackColor = true;

                Text = "Application Error";
                ClientSize = new Size(430, 270);
                MinimumSize = new Size(360, 245);
                MaximizeBox = false;
                MinimizeBox = false;
                ShowIcon = false;

                Controls.Add(PictureBox);
                Controls.Add(Label);
                Controls.Add(TextBox);
                Controls.Add(Button);

                ResumeLayout(false);
                PerformLayout();
            }

        }

        #endregion

    }

    #region " Public Types "

    internal sealed class DnsClient
    {

        #region " Properties "

        public IPAddress PreferredDnsServer
        {
            get { return _PreferredDnsServer; }
            set
            {
                _PreferredDnsServer = value;
                ClearCache();
            }
        }

        public IPAddress AlternateDnsServer
        {
            get { return _AlternateDnsServer; }
            set
            {
                _AlternateDnsServer = value;
                ClearCache();
            }
        }

        public bool IgnoreHostsFile
        {
            get { return _IgnoreHostsFile; }
            set
            {
                _IgnoreHostsFile = value;
                ClearCache();
            }
        }

        public bool IgnoreResolverCache
        {
            get { return _IgnoreResolverCache; }
            set
            {
                _IgnoreResolverCache = value;
                ClearCache();
            }
        }

        public bool SystemDnsFallback
        {
            get { return _SystemDnsFallback; }
            set
            {
                _SystemDnsFallback = value;
                ClearCache();
            }
        }

        public bool CacheDnsResults
        {
            get { return _CacheDnsResults; }
            set
            {
                _CacheDnsResults = value;
                ClearCache();
            }
        }

        public int CacheTTL
        {
            get { return _CacheTTL; }
            set { _CacheTTL = value; }
        }

        #endregion

        #region " Members "

        private IPAddress _PreferredDnsServer;

        private IPAddress _AlternateDnsServer;
        private bool _IgnoreHostsFile;
        private bool _IgnoreResolverCache;

        private bool _SystemDnsFallback;
        private bool _CacheDnsResults;

        private int _CacheTTL;

        private Dictionary<string, DnsResult> Cache;
        #endregion

        #region " Constructor "

        public DnsClient()
        {
            _PreferredDnsServer = new IPAddress(new byte[] { 8, 8, 8, 8 }); //NOTE: Google preferred DNS server
            _AlternateDnsServer = new IPAddress(new byte[] { 8, 8, 4, 4 }); //NOTE: Google alternate DNS server

            _CacheTTL = 900; //NOTE: 15 minutes.

            _IgnoreHostsFile = true;
            _IgnoreResolverCache = true;
            _SystemDnsFallback = true;
            _CacheDnsResults = true;

            Cache = new Dictionary<string, DnsResult>();
        }

        #endregion

        #region " DNS Handling "

        public IPAddress[] Resolve(string hostName)
        {
            IPAddress IP = IPAddress.None;

            //NOTE: If we get an IP address just return it.
            if (IPAddress.TryParse(hostName, out IP))
            {
                if (IP.AddressFamily == AddressFamily.InterNetwork)
                {
                    return new IPAddress[] { IP };
                }
                else
                {
                    //NOTE: For the sake of consistency we should reject IPv6 addresses.
                    throw new NotImplementedException("IPv6 addresses are not supported.");
                }
            }

            if (IsHostNameValid(hostName))
            {
                IPAddress[] AddressList = null;

                //NOTE: Host names should be normalized for caching.
                string Host = hostName.Trim().ToLower();

                if (CacheDnsResults)
                {
                    AddressList = QueryCache(Host);

                    if (!(AddressList.Length == 0))
                    {
                        return AddressList;
                    }
                }

                if (PreferredDnsServer != null)
                {
                    AddressList = GetDnsRecords(Host, PreferredDnsServer);

                    if (!(AddressList.Length == 0))
                    {
                        return CacheResults(Host, AddressList);
                    }
                }

                if (AlternateDnsServer != null)
                {
                    AddressList = GetDnsRecords(Host, AlternateDnsServer);

                    if (!(AddressList.Length == 0))
                    {
                        return CacheResults(Host, AddressList);
                    }
                }

                //NOTE: This is required when resolving LAN host names.
                if (SystemDnsFallback)
                {
                    AddressList = GetDnsRecords(Host, null);

                    if (!(AddressList.Length == 0))
                    {
                        return CacheResults(Host, AddressList);
                    }
                }
            }

            return new IPAddress[] { };
        }

        private IPAddress[] GetDnsRecords(string hostName, IPAddress dnsServer)
        {
            IntPtr QueryList = default(IntPtr);
            List<IPAddress> Addresses = new List<IPAddress>();

            IntPtr reserved = IntPtr.Zero;
            IPv4Array IPv4Array = GetIPv4ArrayFromIPAddress(dnsServer);

            if (DnsQueryA(hostName, 1, 8 | 64, ref IPv4Array, ref QueryList, ref reserved) == 0)
            {
                DnsRecordA Record = (DnsRecordA)Marshal.PtrToStructure(QueryList, typeof(DnsRecordA));
                IPAddress Address = GetAddressFromRecord(Record);

                if (!object.ReferenceEquals(Address, IPAddress.None))
                {
                    Addresses.Add(Address);
                }

                while (!(Record.NextRecord == IntPtr.Zero))
                {
                    Record = (DnsRecordA)Marshal.PtrToStructure(Record.NextRecord, typeof(DnsRecordA));
                    Address = GetAddressFromRecord(Record);

                    if (!object.ReferenceEquals(Address, IPAddress.None))
                    {
                        Addresses.Add(Address);
                    }
                }
            }

            return Addresses.ToArray();
        }

        private IPv4Array GetIPv4ArrayFromIPAddress(IPAddress address)
        {
            IPv4Array IP4rray = new IPv4Array();

            if (address != null)
            {
                IP4rray.Count = 1;
                IP4rray.Addresses = new uint[] { BitConverter.ToUInt32(address.GetAddressBytes(), 0) };
            }

            return IP4rray;
        }

        private IPAddress GetAddressFromRecord(DnsRecordA record)
        {
            if (!(record.Type == 1))
            {
                return IPAddress.None;
            }

            if (!((record.Flags & 3) < 2))
            {
                return IPAddress.None;
            }

            return new IPAddress(record.Data);
        }

        #endregion

        #region " Cache Handling "

        private void ClearCache()
        {
            Cache.Clear();
        }

        private IPAddress[] QueryCache(string hostName)
        {
            if (Cache.ContainsKey(hostName))
            {
                DnsResult Result = Cache[hostName];

                if ((System.DateTime.Now - Result.ResolutionTime).TotalSeconds > CacheTTL)
                {
                    Cache.Remove(hostName);
                }
                else
                {
                    return Result.AddressList;
                }
            }

            return new IPAddress[] { };
        }

        private IPAddress[] CacheResults(string hostName, IPAddress[] addressList)
        {
            if (CacheDnsResults)
            {
                Cache.Add(hostName, new DnsResult(addressList));
            }

            return addressList;
        }

        #endregion

        #region " Validation "

        private bool IsHostNameValid(string hostName)
        {
            //NOTE: RFC 2181 [Sec. 11] states a maximum length of 255 characters.
            if (hostName.Length > byte.MaxValue)
            {
                throw new ArgumentOutOfRangeException("hostName", "Host name must not exceed 255 characters.");
            }

            string[] Labels = null;

            if (hostName.Contains("."))
            {
                Labels = hostName.Split('.');
            }
            else
            {
                Labels = new string[] { hostName };
            }

            //NOTE: RFC 952 [Sec. 1] & RFC 1123 [Sec. 2.1] states host names should follow these naming conventions.
            //-Labels (delimited by periods) must be between 1 and 63 characters long.
            //-Labels must start and end with alphanumeric characters.
            //-Host names may only contains letters a-z, digits 0-9, hyphen (-), and periods (.).

            foreach (string Label in Labels)
            {
                if (Label.Length == 0 || Label.Length > 63)
                {
                    throw new FormatException("Labels in host names must be between 1 and 63 characters in length.");
                }

                int FirstChar = Convert.ToInt32(Label[0]);
                int LastChar = Convert.ToInt32(Label[Label.Length - 1]);

                if (!(IsLetterOrDigit(FirstChar) || IsLetterOrDigit(LastChar)))
                {
                    throw new FormatException("Labels in host names must begin and end with alphanumeric ASCII characters.");
                }

                for (int I = 1; I <= Label.Length - 2; I++)
                {
                    int Value = Convert.ToInt32(Label[I]);

                    if (!(IsLetterOrDigit(Value) || IsHyphen(Value)))
                    {
                        throw new FormatException("Host names may only contain alphanumeric ASCII characters, hyphens (-), and periods (.).");
                    }
                }
            }

            return true;
        }

        private bool IsLetterOrDigit(int value)
        {
            return (value >= 48 && value <= 57) || (value >= 65 && value <= 90) || (value >= 97 && value <= 122);
        }

        private bool IsHyphen(int value)
        {
            return value == 45;
        }

        #endregion

        #region " Win32 "

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_A")]
        private static extern int DnsQueryA(string hostName, short type, int options, ref IPv4Array dnsServers, ref IntPtr recordList, ref IntPtr reserved);

        #endregion

        #region " Type Definitions "

        private class DnsResult
        {

            public readonly System.DateTime ResolutionTime;

            public readonly IPAddress[] AddressList;
            public DnsResult(IPAddress[] addressesList)
            {
                this.ResolutionTime = System.DateTime.Now;
                this.AddressList = addressesList;
            }

        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct DnsRecordA
        {
            public IntPtr NextRecord;
            public string Name;
            public short Type;
            public short DataLength;
            public int Flags;
            public int Ttl;
            public int Reserved;
            public uint Data;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IPv4Array
        {
            public int Count;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.U4)]
            public uint[] Addresses;
        }

        #endregion

    }

    internal sealed class HttpClient
    {

        #region " Properties "

        public bool BypassPageCaching
        {
            get { return _BypassPageCaching; }
            set { _BypassPageCaching = value; }
        }

        public int RequestThrottleTime
        {
            get { return _RequestThrottleTime; }
            set { _RequestThrottleTime = Math.Max(value, 0); }
        }

        public int MaxConcurrentRequests
        {
            get { return _MaxConcurrentRequests; }
            set { _MaxConcurrentRequests = Math.Max(value, 0); }
        }

        public int RetryDelayTime
        {
            get { return _RetryDelayTime; }
            set { _RetryDelayTime = Math.Max(value, 0); }
        }

        #endregion

        #region " Events "

        public event WebRequestDownloadProgressEventHandler WebRequestDownloadProgress;
        public delegate void WebRequestDownloadProgressEventHandler(object sender, WebRequestProgressEventArgs e);

        public event WebRequestUploadProgressEventHandler WebRequestUploadProgress;
        public delegate void WebRequestUploadProgressEventHandler(object sender, WebRequestProgressEventArgs e);

        public event WebRequestCompletedEventHandler WebRequestCompleted;
        public delegate void WebRequestCompletedEventHandler(object sender, WebRequestCompletedEventArgs e);

        public event WebRequestResolveHostEventHandler WebRequestResolveHost;
        public delegate void WebRequestResolveHostEventHandler(object sender, WebRequestResolveHostEventArgs e);

        #endregion

        #region " Members "

        private int _RetryDelayTime;
        private int _ConcurrentRequests;
        private int _RequestThrottleTime;
        private int _MaxConcurrentRequests;
        private bool _BypassPageCaching;
        private System.DateTime _RequestTime;

        private object _ThrottleLock;
        #endregion

        #region " Constructor "

        public HttpClient()
        {
            _BypassPageCaching = true;
            _RetryDelayTime = 1000;
            _ThrottleLock = new object();

            ServicePointManager.CheckCertificateRevocationList = false;
            ServicePointManager.DnsRefreshTimeout = Timeout.Infinite;
            ServicePointManager.EnableDnsRoundRobin = false;
        }

        #endregion

        #region " Request Handling "

        public byte[] DownloadData(string host)
        {
            RequestOptions Options = new RequestOptions();
            Options.Method = "GET";

            return UploadValues(host, null, Options);
        }

        public byte[] UploadValues(string host, Dictionary<string, object> values)
        {
            return UploadValues(host, values, null);
        }

        public byte[] UploadValues(string host, Dictionary<string, object> values, RequestOptions options)
        {
            if (options == null)
            {
                options = new RequestOptions();
            }

            return ExecuteRequest(host, values, new RequestState(options, null, false));
        }

        public void DownloadDataAsync(string host)
        {
            RequestOptions Options = new RequestOptions();
            Options.Method = "GET";

            UploadValuesAsync(host, null, Options, null);
        }

        public void DownloadDataAsync(string host, object userState)
        {
            RequestOptions Options = new RequestOptions();
            Options.Method = "GET";

            UploadValuesAsync(host, null, Options, userState);
        }

        public void UploadValuesAsync(string host, Dictionary<string, object> values)
        {
            UploadValuesAsync(host, values, null, null);
        }

        public void UploadValuesAsync(string host, Dictionary<string, object> values, object userState)
        {
            UploadValuesAsync(host, values, null, userState);
        }

        public void UploadValuesAsync(string host, Dictionary<string, object> values, RequestOptions options)
        {
            UploadValuesAsync(host, values, options, null);
        }

        public void UploadValuesAsync(string host, Dictionary<string, object> values, RequestOptions options, object userState)
        {
            if (options == null)
            {
                options = new RequestOptions();
            }

            ThreadPool.QueueUserWorkItem((object obj) => ExecuteRequest(host, values, new RequestState(options, userState, true)));
        }

        private void ThrottleRequest()
        {
            while (true)
            {
                TimeSpan ElapsedTime = default(TimeSpan);
                int CurrentRequests = _ConcurrentRequests;

                if (_RequestThrottleTime == 0)
                {
                    ElapsedTime = TimeSpan.MaxValue;
                }
                else
                {
                    lock (_ThrottleLock)
                    {
                        ElapsedTime = (System.DateTime.Now - _RequestTime);
                    }
                }

                if (_MaxConcurrentRequests == 0)
                {
                    CurrentRequests = -1;
                }

                if ((ElapsedTime.TotalMilliseconds > _RequestThrottleTime) && (CurrentRequests < _MaxConcurrentRequests))
                {
                    break;
                }

                Thread.Sleep(15);
            }
        }

        private byte[] ExecuteRequest(string host, Dictionary<string, object> values, RequestState state)
        {
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            Thread.CurrentThread.CurrentUICulture = CultureInfo.InvariantCulture;

            int Count = 0;
            WebRequest Request = null;
            Exception Error = null;
            byte[] Result = null;
            WebHeaderCollection Headers = null;

            while (state.Options.RetryCount >= Count)
            {
                if ((_RequestThrottleTime > 0) || (_MaxConcurrentRequests > 0))
                {
                    ThrottleRequest();
                }

                lock (_ThrottleLock)
                {
                    if (System.DateTime.Now > _RequestTime)
                    {
                        _RequestTime = System.DateTime.Now;
                    }
                }

                Interlocked.Increment(ref _ConcurrentRequests);

                try
                {
                    Request = null;
                    Error = null;
                    Result = null;

                    Uri Address = PrepareUri(host, values, state.Options);
                    Request = PrepareWebRequest(Address, state.Options);

                    if ((values != null) && (state.Options.Method == "POST"))
                    {
                        WriteRequest(Request, values, state);
                    }

                    WebResponse Response = Request.GetResponse();

                    Result = ReadResponse(Response, state);
                    Headers = Response.Headers;

                    Interlocked.Decrement(ref _ConcurrentRequests);

                    break;
                }
                catch (Exception ex)
                {
                    Error = ex;
                }

                Count += 1;
                Interlocked.Decrement(ref _ConcurrentRequests);

                Thread.Sleep(RetryDelayTime);
            }

            if (state.RaiseEvents)
            {
                WebRequestCompletedEventArgs EventArgs = new WebRequestCompletedEventArgs(Error, Result, Headers, state.UserState);

                if (WebRequestCompleted != null)
                {
                    WebRequestCompleted(this, EventArgs);
                }
            }
            else if (Error != null)
            {
                throw Error;
            }

            return Result;
        }

        private Uri PrepareUri(string host, Dictionary<string, object> values, RequestOptions options)
        {
            UriBuilder UriBuilder = new UriBuilder(host);
            StringBuilder StringBuilder = new StringBuilder();

            if (UriBuilder.Query.Length > 0)
            {
                StringBuilder.AppendFormat("{0}&", UriBuilder.Query.Substring(1));
            }

            if ((values != null) && (options.Method == "GET"))
            {
                foreach (KeyValuePair<string, object> K in values)
                {
                    StringBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(K.Key), Uri.EscapeDataString(K.Value.ToString()));
                }

                StringBuilder.Length -= 1;
            }

            if (_BypassPageCaching)
            {
                StringBuilder.Append(Guid.NewGuid().ToString().Remove(8));
            }

            UriBuilder.Query = StringBuilder.ToString();

            return UriBuilder.Uri;
        }

        private HttpWebRequest PrepareWebRequest(Uri address, RequestOptions options)
        {
            HttpWebRequest HttpRequest = (HttpWebRequest)WebRequest.Create(address);

            HttpRequest.Accept = null;
            HttpRequest.AllowAutoRedirect = true;
            HttpRequest.AllowWriteStreamBuffering = false;
            HttpRequest.AuthenticationLevel = AuthenticationLevel.None;
            HttpRequest.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            HttpRequest.CachePolicy = new RequestCachePolicy(RequestCacheLevel.BypassCache);
            HttpRequest.ClientCertificates = new X509CertificateCollection();
            HttpRequest.ConnectionGroupName = null;
            HttpRequest.ContentLength = 0;
            HttpRequest.ContinueDelegate = null;
            HttpRequest.Credentials = null;
            HttpRequest.CookieContainer = options.Cookies;
            HttpRequest.Expect = null;
            HttpRequest.ImpersonationLevel = TokenImpersonationLevel.None;
            HttpRequest.KeepAlive = true;
            HttpRequest.MaximumAutomaticRedirections = 10;
            HttpRequest.MaximumResponseHeadersLength = -1;
            HttpRequest.MediaType = null;
            HttpRequest.Method = options.Method;
            HttpRequest.Pipelined = true;
            HttpRequest.PreAuthenticate = false;
            HttpRequest.ProtocolVersion = HttpVersion.Version11;
            HttpRequest.Proxy = options.Proxy;
            HttpRequest.ReadWriteTimeout = options.Timeout;
            HttpRequest.Referer = options.Referer;
            HttpRequest.SendChunked = false;
            HttpRequest.Timeout = options.Timeout;
            HttpRequest.TransferEncoding = null;
            HttpRequest.UnsafeAuthenticatedConnectionSharing = true;
            HttpRequest.UseDefaultCredentials = false;
            HttpRequest.UserAgent = options.UserAgent;

            HttpRequest.ServicePoint.BindIPEndPointDelegate = BindIPEndPoint;
            HttpRequest.ServicePoint.ConnectionLeaseTimeout = 60000;
            HttpRequest.ServicePoint.ConnectionLimit = 100;
            HttpRequest.ServicePoint.Expect100Continue = false;
            HttpRequest.ServicePoint.MaxIdleTime = 10000;
            HttpRequest.ServicePoint.ReceiveBufferSize = ushort.MaxValue;
            HttpRequest.ServicePoint.UseNagleAlgorithm = true;

            if (_BypassPageCaching)
            {
                HttpRequest.Headers["Cache-Control"] = "no-cache, no-store, no-transform";
                HttpRequest.Headers["Pragma"] = "no-cache";
            }

            if (options.Headers != null)
            {
                HttpRequest.Headers.Add(options.Headers);
            }

            return HttpRequest;
        }

        private byte[] PrepareRequestStream(Dictionary<string, object> values, string boundary)
        {
            MemoryStream MemoryStream = new MemoryStream();
            StreamWriter StreamWriter = new StreamWriter(MemoryStream);

            //NOTE: RFC 2388 describes the format of multipart/form-data POST requests.

            bool IsBinary = false;

            foreach (KeyValuePair<string, object> K in values)
            {
                IsBinary = (K.Value is byte[]);

                StreamWriter.WriteLine(string.Format("--{0}", boundary));
                StreamWriter.WriteLine(string.Format("Content-Disposition: form-data; name=\"{0}\"", K.Key));

                if (IsBinary)
                {
                    StreamWriter.WriteLine("Content-Type: application/octet-stream");
                }

                StreamWriter.WriteLine();

                if (IsBinary)
                {
                    byte[] ValueData = (byte[])K.Value;

                    StreamWriter.Flush();
                    MemoryStream.Write(ValueData, 0, ValueData.Length);

                    StreamWriter.WriteLine();
                }
                else
                {
                    StreamWriter.WriteLine(K.Value);
                }
            }

            StreamWriter.WriteLine(string.Format("--{0}--", boundary));
            StreamWriter.Close();

            return MemoryStream.ToArray();
        }

        private void WriteRequest(WebRequest request, Dictionary<string, object> values, RequestState state)
        {
            if (values.Count == 0)
            {
                return;
            }

            string Boundary = System.DateTime.UtcNow.Ticks.ToString();
            byte[] Data = PrepareRequestStream(values, Boundary);

            request.ContentType = string.Format("multipart/form-data; boundary={0}", Boundary);
            request.ContentLength = Data.Length;

            int BytesToWrite = 0;
            int BytesTransferred = 0;

            Stream RequestStream = request.GetRequestStream();

            while (true)
            {
                if (state.RaiseEvents)
                {
                    if (WebRequestUploadProgress != null)
                    {
                        WebRequestUploadProgress(this, new WebRequestProgressEventArgs(BytesTransferred, Data.Length, state.UserState));
                    }
                }

                BytesToWrite = Math.Min(ushort.MaxValue, Data.Length - BytesTransferred);

                if (BytesToWrite == 0)
                {
                    break;
                }

                RequestStream.Write(Data, BytesTransferred, BytesToWrite);
                BytesTransferred += BytesToWrite;
            }
        }

        private byte[] ReadResponse(WebResponse response, RequestState state)
        {
            MemoryStream MemoryStream = new MemoryStream();

            int Length = Convert.ToInt32(response.ContentLength);

            int BytesRead = 0;
            int BytesTransferred = 0;

            byte[] Buffer = new byte[ushort.MaxValue];
            Stream ResponseStream = response.GetResponseStream();

            while (true)
            {
                if (state.RaiseEvents)
                {
                    if (Length == -1)
                    {
                        if (WebRequestDownloadProgress != null)
                        {
                            WebRequestDownloadProgress(this, new WebRequestProgressEventArgs(BytesTransferred, BytesTransferred, state.UserState));
                        }
                    }
                    else
                    {
                        if (WebRequestDownloadProgress != null)
                        {
                            WebRequestDownloadProgress(this, new WebRequestProgressEventArgs(BytesTransferred, Length, state.UserState));
                        }
                    }
                }

                BytesRead = ResponseStream.Read(Buffer, 0, Buffer.Length);

                if (BytesRead == 0)
                {
                    break;
                }

                MemoryStream.Write(Buffer, 0, BytesRead);
                BytesTransferred += BytesRead;
            }

            response.Close();
            MemoryStream.Close();

            return MemoryStream.ToArray();
        }

        #endregion

        #region " Resolve Host "

        private IPEndPoint BindIPEndPoint(ServicePoint servicePoint, IPEndPoint remoteEndPoint, int retryCount)
        {
            string HostName = servicePoint.Address.DnsSafeHost.ToLower();
            WebRequestResolveHostEventArgs EventArgs = new WebRequestResolveHostEventArgs(HostName, remoteEndPoint.Address);

            if (WebRequestResolveHost != null)
            {
                WebRequestResolveHost(this, EventArgs);
            }

            remoteEndPoint.Address = EventArgs.Address;

            return null;
        }

        #endregion

        #region " Type Definitions "

        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public sealed class WebRequestResolveHostEventArgs
        {

            #region " Properties "

            public string HostName
            {
                get { return _HostName; }
            }

            public IPAddress Address
            {
                get { return _Address; }
                set { _Address = value; }
            }

            #endregion

            #region " Members "

            private string _HostName;

            private IPAddress _Address;
            #endregion

            #region " Constructor "

            public WebRequestResolveHostEventArgs(string hostName, IPAddress address)
            {
                _HostName = hostName;
                _Address = address;
            }

            #endregion

        }

        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public sealed class WebRequestCompletedEventArgs
        {

            #region " Properties "

            public Exception Error
            {
                get { return _Error; }
            }

            public byte[] Result
            {
                get { return _Result; }
            }

            public WebHeaderCollection Headers
            {
                get { return _Headers; }
            }

            public object UserState
            {
                get { return _UserState; }
            }

            #endregion

            #region " Members "

            private Exception _Error;
            private byte[] _Result;
            private WebHeaderCollection _Headers;

            private object _UserState;
            #endregion

            #region " Constructor "

            public WebRequestCompletedEventArgs(Exception error, byte[] result, WebHeaderCollection headers, object userState)
            {
                _Error = error;
                _Result = result;
                _Headers = headers;
                _UserState = userState;
            }

            #endregion

        }

        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public sealed class WebRequestProgressEventArgs
        {

            #region " Properties "

            public double ProgressPercentage
            {
                get { return _ProgressPercentage; }
            }

            public int BytesTransferred
            {
                get { return _BytesTransferred; }
            }

            public int TotalBytesToTransfer
            {
                get { return _TotalBytesToTransfer; }
            }

            public object UserState
            {
                get { return _UserState; }
            }

            #endregion

            #region " Members "

            private double _ProgressPercentage;
            private int _BytesTransferred;
            private int _TotalBytesToTransfer;

            private object _UserState;
            #endregion

            #region " Constructor "

            public WebRequestProgressEventArgs(int bytesTransferred, int totalBytesToTransfer, object userState)
            {
                _BytesTransferred = bytesTransferred;
                _TotalBytesToTransfer = totalBytesToTransfer;

                if (!(totalBytesToTransfer == 0))
                {
                    _ProgressPercentage = (_BytesTransferred / _TotalBytesToTransfer) * 100;
                }

                _UserState = userState;
            }

            #endregion

        }

        public sealed class RequestOptions
        {

            #region " Properties "

            public IWebProxy Proxy
            {
                get { return _Proxy; }
                set { _Proxy = value; }
            }

            public string UserAgent
            {
                get { return _UserAgent; }
                set { _UserAgent = value; }
            }

            public string Referer
            {
                get { return _Referer; }
                set { _Referer = value; }
            }

            public CookieContainer Cookies
            {
                get { return _Cookies; }
                set { _Cookies = value; }
            }

            public WebHeaderCollection Headers
            {
                get { return _Headers; }
                set { _Headers = value; }
            }

            public int Timeout
            {
                get { return _Timeout; }
                set { _Timeout = value; }
            }

            public int RetryCount
            {
                get { return _RetryCount; }
                set { _RetryCount = Math.Max(value, 0); }
            }

            public string Method
            {
                get { return _Method; }
                set
                {
                    if (string.IsNullOrEmpty(value))
                    {
                        _Method = "POST";
                    }
                    else
                    {
                        _Method = value.Trim().ToUpper();
                    }
                }
            }

            #endregion

            #region " Members "

            private IWebProxy _Proxy;
            private string _UserAgent;
            private string _Referer;
            private CookieContainer _Cookies;
            private WebHeaderCollection _Headers;
            private int _Timeout;
            private int _RetryCount;

            private string _Method;
            #endregion

            #region " Constructor "

            public RequestOptions()
            {
                _Method = "POST";
                _Timeout = 60000;
                _Proxy = WebRequest.DefaultWebProxy;
                _Cookies = new CookieContainer();
                _Headers = new WebHeaderCollection();
            }

            #endregion

        }

        private sealed class RequestState
        {

            #region " Properties "

            public RequestOptions Options
            {
                get { return _Options; }
            }

            public object UserState
            {
                get { return _UserState; }
            }

            public bool RaiseEvents
            {
                get { return _RaiseEvents; }
            }

            #endregion

            #region " Members "

            private RequestOptions _Options;
            private object _UserState;

            private bool _RaiseEvents;
            #endregion

            #region " Constructor "

            public RequestState(RequestOptions options, object userState, bool raiseEvents)
            {
                _Options = options;
                _UserState = userState;
                _RaiseEvents = raiseEvents;
            }

            #endregion

        }

        #endregion

        public static int EstimateMaxTimeout(int numberOfBytes)
        {
            int GracePeriod = 5000;
            //5 seconds to establish a connection.
            int TimePerChunk = 1000;
            //We'll assume each chunk takes 1 second.
            int TransferSpeed = 32000;
            //256 Kbps download / upload speed.
            int NumberOfChunks = Convert.ToInt32(Math.Ceiling((double)(numberOfBytes / TransferSpeed)));

            return GracePeriod + (NumberOfChunks * TimePerChunk);
        }

    }

    internal sealed class BlogPost
    {

        /// <summary>
        /// Gets the unique id for the post.
        /// </summary>
        public int Id
        {
            get { return _Id; }
        }

        /// <summary>
        /// Gets the title for the post.
        /// </summary>
        public string Title
        {
            get { return _Title; }
        }

        /// <summary>
        /// Gets the number of times the post has been read by users.
        /// </summary>
        public int TimesRead
        {
            get { return _TimesRead; }
        }

        /// <summary>
        /// Gets the date that the post was originally posted.
        /// </summary>
        public System.DateTime DatePosted
        {
            get { return _DatePosted; }
        }

        private int _Id;
        private string _Title;
        private int _TimesRead;
        private System.DateTime _DatePosted;

        private Delegate _GetPostBodyDelegate;
        public BlogPost(int id, string title, int timesRead, System.DateTime datePosted, Delegate getPostBodyDelegate)
        {
            _Id = id;
            _Title = title;
            _TimesRead = timesRead;
            _DatePosted = datePosted;
            _GetPostBodyDelegate = getPostBodyDelegate;
        }

        /// <summary>
        /// Gets the body for the post.
        /// </summary>
        public string GetPostBody()
        {
            return (string)_GetPostBodyDelegate.DynamicInvoke(_Id);
        }

    }

    internal sealed class BrokerSettings
    {


        /// <summary>
        /// Gets or sets the theme that will be used by the authentication dialog.
        /// </summary>
        public DialogTheme DialogTheme { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to catch unhandled exceptions and report them to the server.
        /// </summary>
        public bool CatchUnhandledExceptions { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to ignore automatic updates.
        /// </summary>
        public bool DeferAutomaticUpdates { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the authentication window will be shown. This option should only be used in
        /// products that provide lifetime licenses.
        /// </summary>
        public bool SilentAuthentication { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to verify the integrity of core runtime files (mscorlib, System, and System.Security). 
        /// </summary>
        public bool VerifyRuntimeIntegrity { get; set; }


        public BrokerSettings()
        {
            CatchUnhandledExceptions = true;
            VerifyRuntimeIntegrity = true;
            DialogTheme = NetSeal.DialogTheme.Light;
        }

    }

    internal enum DialogTheme : int
    {
        None = 0,
        Light = 1,
        Dark = 2
    }

    internal enum LicenseType : byte
    {
        Special = 0,
        Bronze = 1,
        Silver = 2,
        Gold = 3,
        Platinum = 4,
        Diamond = 5
    }

    #endregion

}