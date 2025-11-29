
import java.util.Random;

public class InsecureRandom {
    public int generateSecretToken() {
        // Use of insecure random number generator for security-sensitive context
        Random random = new Random();
        return random.nextInt();
    }
}
