
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.codec.binary.Base64;

public class InsecureDeserialization {
    public void vulnerable(HttpServletRequest request) throws Exception {
        String data = request.getParameter("data");
        byte[] decodedData = Base64.decodeBase64(data);
        ByteArrayInputStream bais = new ByteArrayInputStream(decodedData);
        // Vulnerable to Insecure Deserialization
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
    }
}
