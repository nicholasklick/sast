
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class WeakHashing {
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        // Use of a weak hashing algorithm (MD5)
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        return md5.digest(password.getBytes());
    }
}
