// Insecure Deserialization vulnerabilities in C#
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.Script.Serialization;
using Newtonsoft.Json;

public class DeserializationVulnerabilities
{
    public object DeserializeBinary(byte[] data)
    {
        // VULNERABLE: BinaryFormatter is dangerous with untrusted data
        BinaryFormatter formatter = new BinaryFormatter();
        using (MemoryStream ms = new MemoryStream(data))
        {
            return formatter.Deserialize(ms);
        }
    }

    public object DeserializeJson(string json)
    {
        // VULNERABLE: TypeNameHandling.All allows type injection
        JsonSerializerSettings settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };
        return JsonConvert.DeserializeObject(json, settings);
    }

    public object DeserializeJavaScript(string input)
    {
        // VULNERABLE: JavaScriptSerializer with untrusted input
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        return serializer.DeserializeObject(input);
    }

    public T DeserializeXml<T>(string xml)
    {
        // VULNERABLE: XmlSerializer with user-controlled type
        System.Xml.Serialization.XmlSerializer serializer =
            new System.Xml.Serialization.XmlSerializer(typeof(T));
        using (StringReader reader = new StringReader(xml))
        {
            return (T)serializer.Deserialize(reader);
        }
    }
}
