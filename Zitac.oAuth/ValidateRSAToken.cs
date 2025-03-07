using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Flow.CoreSteps;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Zitac.oAuth;

[AutoRegisterStep("Validate RSA Token", "Integration", "oAuth")]
[Writable]
public class ValidateToken : BaseFlowAwareStep, ISyncStep, IDataConsumer, IDataProducer
{
    public DataDescription[] InputData
    {
        get
        {
            List<DataDescription> dataDescriptionList = new List<DataDescription>();
            dataDescriptionList.Add(new DataDescription((DecisionsType)new DecisionsNativeType(typeof(String)), "Token String"));
            dataDescriptionList.Add(new DataDescription((DecisionsType)new DecisionsNativeType(typeof(String)), "Modulus (n)"));
            dataDescriptionList.Add(new DataDescription((DecisionsType)new DecisionsNativeType(typeof(String)), "Exponent (e)"));
            dataDescriptionList.Add(new DataDescription((DecisionsType)new DecisionsNativeType(typeof(String)), "Valid Issuer"));
            return dataDescriptionList.ToArray();
        }
    }

    public override OutcomeScenarioData[] OutcomeScenarios
    {
        get
        {
            List<OutcomeScenarioData> outcomeScenarioDataList = new List<OutcomeScenarioData>();

            outcomeScenarioDataList.Add(new OutcomeScenarioData("True"));
            outcomeScenarioDataList.Add(new OutcomeScenarioData("False", new DataDescription(typeof(string), "Validation Error")));
            return outcomeScenarioDataList.ToArray();
        }
    }

    public ResultData Run(StepStartData data)
    {
        try
        {
            string token = data.Data["Token String"] as string;
            string n = data.Data["Modulus (n)"] as string;
            string e = data.Data["Exponent (e)"] as string;
            string validIssuer = data.Data["Valid Issuer"] as string;

            // Parse the token manually to avoid framework caching issues
            string[] tokenParts = token.Split('.');
            if (tokenParts.Length != 3)
            {
                return new ResultData("False", new Dictionary<string, object>
                {
                    { "Validation Error", "Invalid token format" }
                });
            }

            string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(tokenParts[0]));
            string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(tokenParts[1]));
            
            // Parse the header and payload
            var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerJson);
            var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payloadJson);

            // Check issuer if provided
            if (!string.IsNullOrEmpty(validIssuer))
            {
                if (!payload.TryGetValue("iss", out var issElement) || 
                    issElement.GetString() != validIssuer)
                {
                    return new ResultData("False", new Dictionary<string, object>
                    {
                        { "Validation Error", $"Invalid issuer. Expected: {validIssuer}" }
                    });
                }
            }

            // Verify the signature
            string dataToVerify = tokenParts[0] + "." + tokenParts[1];
            byte[] signature = Base64UrlDecode(tokenParts[2]);
            
            // Create RSA object with the provided parameters
            using (var rsa = RSA.Create())
            {
                try
                {
                    // Convert Base64 URL encoded strings to byte arrays
                    var modulusBytes = Base64UrlDecode(n);
                    var exponentBytes = Base64UrlDecode(e);

                    // Create RSA parameters
                    RSAParameters rsaParameters = new RSAParameters
                    {
                        Modulus = modulusBytes,
                        Exponent = exponentBytes
                    };

                    // Import the parameters
                    rsa.ImportParameters(rsaParameters);
                    
                    // Determine the signing algorithm from the header
                    string alg = header.TryGetValue("alg", out var algElement) ? algElement.GetString() : "RS256";
                    
                    // Choose the appropriate hash algorithm
                    HashAlgorithmName hashAlgorithm;
                    switch (alg)
                    {
                        case "RS256":
                            hashAlgorithm = HashAlgorithmName.SHA256;
                            break;
                        case "RS384":
                            hashAlgorithm = HashAlgorithmName.SHA384;
                            break;
                        case "RS512":
                            hashAlgorithm = HashAlgorithmName.SHA512;
                            break;
                        default:
                            return new ResultData("False", new Dictionary<string, object>
                            {
                                { "Validation Error", $"Unsupported algorithm: {alg}" }
                            });
                    }
                    
                    // Verify the signature
                    byte[] dataBytes = Encoding.ASCII.GetBytes(dataToVerify);
                    bool isValid = rsa.VerifyData(dataBytes, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
                    
                    if (isValid)
                    {
                        return new ResultData("True");
                    }
                    else
                    {
                        return new ResultData("False", new Dictionary<string, object>
                        {
                            { "Validation Error", "Invalid signature" }
                        });
                    }
                }
                catch (Exception ex)
                {
                    return new ResultData("False", new Dictionary<string, object>
                    {
                        { "Validation Error", $"Signature verification error: {ex.Message}" }
                    });
                }
            }
        }
        catch (Exception ex)
        {
            return new ResultData("False", new Dictionary<string, object>
            {
                { "Validation Error", $"General error: {ex.Message}" }
            });
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        string output = input;
        output = output.Replace('-', '+'); // 62nd char of encoding
        output = output.Replace('_', '/'); // 63rd char of encoding
        
        // Pad with trailing '='s
        switch (output.Length % 4)
        {
            case 0: break; // No pad chars in this case
            case 2: output += "=="; break; // Two pad chars
            case 3: output += "="; break; // One pad char
            default: throw new System.Exception("Illegal base64url string!");
        }
        
        return Convert.FromBase64String(output); // Standard base64 decoder
    }
}