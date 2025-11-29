
public class SystemExit {
    public void doExit() {
        // Calling System.exit() can lead to denial of service
        System.exit(1);
    }
}
