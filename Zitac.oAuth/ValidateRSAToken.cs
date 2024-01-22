using DecisionsFramework.Design.Flow;
using DecisionsFramework.Design.ConfigurationStorage.Attributes;
using DecisionsFramework.Design.Flow.Mapping;
using DecisionsFramework.Design.Flow.CoreSteps;
using System.Security.Cryptography;
using System.Text;

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
            return dataDescriptionList.ToArray();
        }
    }

    public override OutcomeScenarioData[] OutcomeScenarios
    {
        get
        {
            List<OutcomeScenarioData> outcomeScenarioDataList = new List<OutcomeScenarioData>();

            outcomeScenarioDataList.Add(new OutcomeScenarioData("True"));
            outcomeScenarioDataList.Add(new OutcomeScenarioData("False"));
            return outcomeScenarioDataList.ToArray();
        }
    }

    public ResultData Run(StepStartData data)
    {
        string tokenStr = data.Data["Token String"] as string;
        string modulus = data.Data["Modulus (n)"] as string;
        string exponent = data.Data["Exponent (e)"] as string;
 
        string[] tokenParts = tokenStr.Split('.');

        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(
          new RSAParameters()
          {
              Modulus = FromBase64Url(modulus),
              Exponent = FromBase64Url(exponent)
          });

        SHA256 sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

        RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
        rsaDeformatter.SetHashAlgorithm("SHA256");
        if (rsaDeformatter.VerifySignature(hash, FromBase64Url(tokenParts[2])))
        {
            return new ResultData("True");
        }
        else
        {
            return new ResultData("False");
        }


        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

    }

}
