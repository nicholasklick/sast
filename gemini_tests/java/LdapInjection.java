import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import java.util.Hashtable;

public class LdapInjection {
    public void vulnerableLdapSearch(String username) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.provider.url", "ldap://localhost:389/dc=example,dc=com");

        DirContext ctx = new InitialDirContext(env);

        // --- VULNERABLE CODE ---
        // User input is concatenated directly into the LDAP search filter.
        // An attacker can use input like "*)(uid=*))(|(uid=*" to bypass checks.
        // CWE-90: Improper Neutralization of Special Elements used in an LDAP Query
        String filter = "(uid=" + username + ")";
        ctx.search("ou=users", filter, new SearchControls());
        // -----------------------

        ctx.close();
    }
}