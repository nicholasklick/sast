
public class PublicCloneable {
    // Implementing clone() on a non-cloneable class can be a security risk
    public class MyObject implements Cloneable {
        @Override
        public Object clone() throws CloneNotSupportedException {
            return super.clone();
        }
    }
}
