// See https://aka.ms/new-console-template for more information
using System;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Web;


PutBlobWithPath();

PutBlob();

string GetCanonicalizedResource(Uri address, string storageAccountName)
{
    // The absolute path will be "/" because for we're getting a list of containers.
    StringBuilder sb = new StringBuilder("/").Append(storageAccountName).Append(address.AbsolutePath);

    // Address.Query is the resource, such as "?comp=list".
    // This ends up with a NameValueCollection with 1 entry having key=comp, value=list.
    // It will have more entries if you have more query parameters.
    NameValueCollection values = HttpUtility.ParseQueryString(address.Query);

    foreach (var item in values.AllKeys.OrderBy(k => k))
    {
        sb.Append('\n').Append(item.ToLower()).Append(':').Append(values[item]);
    }

    return sb.ToString();
}

string GetAuthorizationHeader(string method, string storageAccountName, string storageAccountKey, 
    string canonicalizedHeaders, string canonicalResources, long contentLength = 0, string ifMatch = "", string md5 = "")
{
    // This is the raw representation of the message signature.
    String MessageSignature = String.Format("{0}\n\n\n{1}\n{5}\n\n\n\n{2}\n\n\n\n{3}{4}",
                method,
                (method == "GET" || method == "HEAD" || (method == "PUT" && contentLength == 0)) ? String.Empty : contentLength.ToString(),
                ifMatch,
                canonicalizedHeaders,
                canonicalResources,
                md5);

    // Now turn it into a byte array.
    byte[] SignatureBytes = Encoding.UTF8.GetBytes(MessageSignature);

    // Create the HMACSHA256 version of the storage key.
    HMACSHA256 SHA256 = new HMACSHA256(Convert.FromBase64String(storageAccountKey));

    // Compute the hash of the SignatureBytes and convert it to a base64 string.
    string signature = Convert.ToBase64String(SHA256.ComputeHash(SignatureBytes));

    // This is the actual header that will be added to the list of request headers.
    return $"SharedKey {storageAccountName}:{signature}";
}

void PutBlobWithPath()
{
    string storageAccountName = "devstoreaccount1"; // Azurite storage account name
    string storageAccountKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="; // Azurite storage account key

    string blobName = "Temp/abc/0AE0AFD11835_AD35230425254881000106590009452543208108318760.xml";
    string filePath = "C:\\teste\\0AE0AFD11835_AD35230425254881000106590009452543208108318760.xml";

    // Construct the URI. It will look like this:
    //  https://{accountName}.blob.core.windows.net/{containerName}/{blobName};
    string uri = $"http://127.0.0.1:10000/{storageAccountName}/landing/{blobName}";
    string method = "PUT";

    string dateTime = "Mon, 04 Sep 2023 23:09:19 GMT"; // DateTime.UtcNow.ToString("R", CultureInfo.InvariantCulture);
    string version = "2019-02-02";

    byte[] fileBytes = File.ReadAllBytes(filePath);
    long contentLength = fileBytes.LongLength;
    MD5 md5 = MD5.Create();
    byte[] md5Hash = md5.ComputeHash(fileBytes);
    string contentMD5 = Convert.ToBase64String(md5Hash);

    // Construct the canonicalized headers string
    string canonicalizedHeaders = $"x-ms-blob-content-md5:{contentMD5}\nx-ms-blob-type:BlockBlob\nx-ms-date:{dateTime}\nx-ms-version:{version}\n";

    // Construct the canonicalized resource string
    string canonicalizedResource = GetCanonicalizedResource(new Uri(uri), storageAccountName);

    // Construct the authentication header
    string authorizationHeader = GetAuthorizationHeader(method, storageAccountName, storageAccountKey,
        canonicalizedHeaders, canonicalizedResource, contentLength);

    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
    request.Method = method;
    request.ContentLength = contentLength;
    request.Headers["x-ms-blob-type"] = "BlockBlob";
    request.Headers["x-ms-blob-content-md5"] = contentMD5;
    request.Headers["x-ms-version"] = version;
    request.Headers["x-ms-date"] = dateTime;
    request.Headers["Authorization"] = authorizationHeader;

    try
    {
        using (Stream requestStream = request.GetRequestStream())
        {
            requestStream.Write(fileBytes, 0, fileBytes.Length);
        }

        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
        {
            Console.WriteLine($"Status: {response.StatusCode} {response.StatusDescription}");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.ToString());
    }
}

void CreateContainer()
{
    string storageAccountName = "devstoreaccount1"; // Azurite storage account name
    string storageAccountKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="; // Azurite storage account key

    // Construct the URI. It will look like this:
    //   https://myaccount.blob.core.windows.net/resource
    string uri = $"http://127.0.0.1:10000/{storageAccountName}/mycontainer?restype=container";
    string method = "PUT";

    string dateTime = DateTime.UtcNow.ToString("R", CultureInfo.InvariantCulture);
    string version = "2019-02-02";

    // Construct the canonicalized headers string
    string canonicalizedHeaders = $"x-ms-date:{dateTime}\nx-ms-version:{version}\n";

    // Construct the canonicalized resource string
    string canonicalizedResource = GetCanonicalizedResource(new Uri(uri), storageAccountName);

    // Construct the authentication header
    string authorizationHeader = GetAuthorizationHeader(method, storageAccountName, storageAccountKey,
        canonicalizedHeaders, canonicalizedResource);

    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
    request.Method = method;
    request.Headers["x-ms-version"] = version;
    request.Headers["x-ms-date"] = dateTime;
    request.Headers["Authorization"] = authorizationHeader;

    try
    {
        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
        {
            Console.WriteLine($"Status: {response.StatusCode} {response.StatusDescription}");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.ToString());
    }
}


void PutBlob()
{
    string accountName = "muriquib69a";
    string accountKey = "uZAIPI9gXH022yIgzUliLOs0sPZVAvvTK4Kx/UoZa+w6dzpVNcYh5oxmWKGcaw/p4Muelk19VxyI+AStuAt5HA==";

    string containerName = "imais2";
    string blobName = "0AE0AFD11835_AD35230425254881000106590009452543208108318760.xml";
    string filePath = "C:\\teste\\0AE0AFD11835_AD35230425254881000106590009452543208108318760.xml";

    // Concatena o URL do blob a partir dos valores fornecidos
    string blobUrl = $"https://{accountName}.blob.core.windows.net/{containerName}/{blobName}";
    //string blobUrl = $"https://{accountName}.blob.core.windows.net/{containerName}/";

    // Lê o arquivo local para enviar para o blob storage
    byte[] fileBytes = File.ReadAllBytes(filePath);

    // Cria um hash MD5 do conteúdo do arquivo
    using (MD5 md5 = MD5.Create())
    {
        byte[] md5Hash = md5.ComputeHash(fileBytes);
        string contentMD5 = Convert.ToBase64String(md5Hash);

        // Cria a solicitação HTTP PUT para enviar o arquivo para o blob storage
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(blobUrl);
        request.Method = "PUT";
        request.ContentLength = fileBytes.LongLength;
        request.Headers["x-ms-blob-type"] = "BlockBlob";
        request.Headers["x-ms-blob-content-md5"] = contentMD5;
        request.Headers["x-ms-version"] = "2019-02-02";
        request.Headers["x-ms-date"] = DateTime.UtcNow.ToString("R");

        // Insere a assinatura da solicitação utilizando a chave de acesso da conta de armazenamento
        string stringToSign = $"PUT\n\n\n{fileBytes.LongLength}\n\n\n\n\n\n\n\n\nx-ms-blob-content-md5:{contentMD5}\nx-ms-blob-type:BlockBlob\nx-ms-date:{request.Headers["x-ms-date"]}\nx-ms-version:{request.Headers["x-ms-version"]}\n/{accountName}/{containerName}/{blobName}";
        byte[] signatureBytes = Encoding.UTF8.GetBytes(stringToSign);
        using (HMACSHA256 hmac = new HMACSHA256(Convert.FromBase64String(accountKey)))
        {
            string signature = Convert.ToBase64String(hmac.ComputeHash(signatureBytes));
            string authorizationHeader = $"SharedKey {accountName}:{signature}";
            request.Headers["Authorization"] = authorizationHeader;
        }

        // Envio dos dados do arquivo para o blob storage
        using (Stream requestStream = request.GetRequestStream())
        {
            requestStream.Write(fileBytes, 0, fileBytes.Length);
        }

        // Envio da solicitação e exibição da resposta do servidor
        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
        {
            Console.WriteLine($"Status: {response.StatusCode} {response.StatusDescription}");
        }
    }
}
