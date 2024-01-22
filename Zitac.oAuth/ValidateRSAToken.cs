using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Flow.CoreSteps;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

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
        string token = data.Data["Token String"] as string;
        string n = data.Data["Modulus (n)"] as string;
        string e = data.Data["Exponent (e)"] as string;
        string validIssuer = data.Data["Valid Issuer"] as string;


        // Convert Base64 URL encoded strings to byte arrays
        var modulusBytes = Base64UrlDecode(n);
        var exponentBytes = Base64UrlDecode(e);

        // Create RSA parameters and import them into an RSA object
        RSAParameters rsaParameters = new RSAParameters
        {
            Modulus = modulusBytes,
            Exponent = exponentBytes
        };

        using (var rsa = RSA.Create())
        {
            rsa.ImportParameters(rsaParameters);

            // Create a token validation parameters object
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(rsa),
                ValidateIssuer = true,
                ValidIssuer = validIssuer,
                ValidateAudience = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                // Validate the token
                tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
                return new ResultData("True");
            }
            catch (Exception ex)
            {
                string ExceptionMessage = ex.Message.ToString();
                return new ResultData("False", (IDictionary<string, object>)new Dictionary<string, object>()
                {
                {
                    "Validation Error",
                    (object) ExceptionMessage
                }
                });
            }
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        string output = input;
        output = output.Replace('-', '+'); // 62nd char of encoding
        output = output.Replace('_', '/'); // 63rd char of encoding
        switch (output.Length % 4) // Pad with trailing '='s
        {
            case 0: break; // No pad chars in this case
            case 2: output += "=="; break; // Two pad chars
            case 3: output += "="; break; // One pad char
            default: throw new System.Exception("Illegal base64url string!");
        }
        return Convert.FromBase64String(output); // Standard base64 decoder
    }

}
