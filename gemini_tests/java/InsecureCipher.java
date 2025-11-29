
import javax.crypto.Cipher;

public class InsecureCipher {
    public Cipher getDesCipher() throws Exception {
        // Use of insecure DES cipher
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
