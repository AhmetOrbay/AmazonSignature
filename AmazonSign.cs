using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace AmazonSignTest
{
    public static  class AmazonSign
    {
        public static readonly Regex CompressWhitespaceRegex = new Regex("\\s+");

        public static string AccessKey = "AKIAIOSFODNN7EXAMPLE";
        public static readonly string awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        private static readonly string Method = "GET";
        public const string ISO8601BasicFormat = "yyyyMMddTHHmmssZ";
        public static DateTime dateTimeStamp = DateTime.Parse("2013-05-24T00:00:00Z", null, System.Globalization.DateTimeStyles.RoundtripKind);
        public static string AwsRegion = "us-east-1";
        public const string SCHEME = "AWS4";
        public const string TERMINATOR = "aws4_request";
        public const string HMACSHA256 = "HMACSHA256";
        public static string ServiceNamedefault = "s3";
        public static string SignedheaderName = string.Empty;

        public static string StandartAuthorization = "AWS4-HMAC-SHA256";


        public static Dictionary<string,string> Authorization()
        {
            var date = dateTimeStamp;
            Dictionary<string, string> result = new();
            var signatures = Signature(date);
            var str = $"{StandartAuthorization} Credential={AccessKey}/{date.ToString("yyyyMMdd")}/{AwsRegion}/{ServiceNamedefault}/{TERMINATOR},SignedHeaders={headerNameOrValueMerge(date).Keys.FirstOrDefault()},Signature={signatures}";
            result.Add(str, dateTimeStamp.ToString(ISO8601BasicFormat));
            return result;
        }


        public static string Signature(DateTime date)
        {
            var StringString = Encoding.UTF8.GetString(Encoding.ASCII.GetBytes(StringToSign(date)));
            var signingKeys = DeriveSigningKey(date.ToString("yyyyMMdd"));//
            var signatureHmac = ToHexString(ComputeKeyedHash(HMACSHA256,signingKeys, StringString),true);
            return signatureHmac;
        }
            

        public static byte[] DeriveSigningKey( string date)
        {

            const string ksecretPrefix = SCHEME;
            char[] ksecret = (ksecretPrefix + awsSecretAccessKey).ToCharArray();
            byte[] hashDate = ComputeKeyedHash(HMACSHA256, Encoding.UTF8.GetBytes(ksecret), date);
            byte[] hashRegion = ComputeKeyedHash(HMACSHA256, hashDate, AwsRegion);
            byte[] hashService = ComputeKeyedHash(HMACSHA256, hashRegion, ServiceNamedefault);
            return ComputeKeyedHash(HMACSHA256, hashService, TERMINATOR);
        }

        public static byte[] ComputeKeyedHash(string algorithm, byte[] key, string data)
        {
            var kha = KeyedHashAlgorithm.Create(algorithm);
            kha.Key = key;
            return kha.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        public static string StringToSign(DateTime date)
        {
            var canonicalRequestHashed = CanonicalRequestHashed(date);
            var scope = dateTimeStamp.ToString("yyyyMMdd") + "/" + AwsRegion + "/" + ServiceNamedefault + "/aws4_request";
            var stringtoString = "AWS4-HMAC-SHA256" + "\n" + date.ToString(ISO8601BasicFormat) + "\n" + scope + "\n" + canonicalRequestHashed;
            return stringtoString;
        }

        public static Dictionary<string,string> headerNameOrValueMerge(DateTime date)
        {
            Dictionary<string, string> result = new();
            Dictionary<string, string> header = new()
            {

                { "host", @"examplebucket.s3.amazonaws.com" },
                { "range", $"bytes=0-9" },
                { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                { "x-amz-date", $"{date.ToString(ISO8601BasicFormat)}" }
                

            };
            var headerTolower = CanonicalizeHeaders(header); //header kismi eklenecek
            var SignedheaderName = CanonicalizeHeaderNames(header);
            result.Add(SignedheaderName, headerTolower);
            return result;
        }

        public static string CanonicalRequestHashed(DateTime date)
        {
            var CanonicalQuery = string.Empty;
            var urlParams = string.Empty;
            var CanonicalUrl = "examplebucket.s3.amazonaws.com/test.txt";
            if (CanonicalUrl.Contains("?"))
            {
                urlParams = CanonicalUrl.Split("?")[1];
            }
            CanonicalUrl = CanonicalUrl.Split("?")[0].Split("com/")[1];
            var Urlencode = UrlEncode(CanonicalUrl,true);
            CanonicalQuery = UrlEncode(urlParams,true);
            var hashedPayload = ToHexString(Sha256Create(""), true);
            var resultHeader = headerNameOrValueMerge(date);
            var CanonicalRequest = Method + "\n/" + Urlencode + "\n" + CanonicalQuery + "\n" + resultHeader.Values.FirstOrDefault() + "\n" + resultHeader.Keys.FirstOrDefault() + "\n" + hashedPayload;
            var conanicalHashed = ToHexString(Sha256Create(CanonicalRequest),true);
            return conanicalHashed;
        }


        public static string ReverseString(string source)
        {
            var stringArray = source.Split(";").Reverse();

            return String.Join(";", stringArray.ToArray()); ;
        }

        public static byte[] Sha256Create(string createData)
        {
            SHA256 sha = SHA256.Create();

            byte[] sourceBytes = Encoding.UTF8.GetBytes(createData);
            byte[] hashBytes = sha.ComputeHash(sourceBytes);
            return hashBytes;
        }

        public static string CanonicalizeHeaderNames(IDictionary<string, string> headers)
        {
            var headersToSign = new List<string>(headers.Keys);
            headersToSign.Sort(StringComparer.OrdinalIgnoreCase);

            var sb = new StringBuilder();
            foreach (var header in headersToSign)
            {
                if (sb.Length > 0) sb.Append(";");
                sb.Append(header.ToLower());
            }
            return sb.ToString();
        }
        
        public static string CanonicalizeHeaders(IDictionary<string, string> headers)
        {
            if (headers == null || headers.Count() == 0) return string.Empty;
            var sortedHeaderMap = new SortedDictionary<string, string>();
            foreach (var header in headers.Keys)
            {
                sortedHeaderMap.Add(header.ToLower(), headers[header].Trim());
            }
            var sb = new StringBuilder();
            foreach (var header in sortedHeaderMap.Keys)
            {
                var headerValue = CompressWhitespaceRegex.Replace(sortedHeaderMap[header], " ");
                sb.AppendFormat("{0}:{1}\n", header.ToLower(), headerValue.Trim());
            }

            return sb.ToString();
        }
        public static string ToHexString(byte[] data, bool lowercase)
        {
            var sb = new StringBuilder(data.Length * 2);
            for (var i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString(lowercase ? "x2" : "X2"));
            }
            return sb.ToString();
        }
        public static string UrlEncode(string url, bool isPath = false)
        {
            const string validUrlCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~=&";

            var encoded = new StringBuilder(url.Length * 2);
            string unreservedChars = String.Concat(validUrlCharacters, (isPath ? "/:" : ""));

            foreach (char symbol in System.Text.Encoding.UTF8.GetBytes(url))
            {
                if (unreservedChars.IndexOf(symbol) != -1)
                    encoded.Append(symbol);
                else
                    encoded.Append("%").Append(String.Format("{0:X2}", (int)symbol));
            }

            return encoded.ToString();
        }
    }

}
