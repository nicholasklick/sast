
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class InsecureExternalizable implements Externalizable {
    // readExternal can be a source of vulnerabilities if not handled carefully
    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        // ... insecure data reading ...
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        // ...
    }
}
