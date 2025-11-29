import javax.persistence.EntityManager;
import javax.persistence.Query;

public class SqlInjectionJpa {
    public void vulnerableJpaQuery(EntityManager em, String customerName) {
        // --- VULNERABLE CODE ---
        // User input is concatenated into a JPQL (Java Persistence Query Language) query.
        // This is still vulnerable to injection, similar to standard SQL.
        // CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
        Query query = em.createQuery("SELECT c FROM Customer c WHERE c.name = '" + customerName + "'");
        query.getResultList();
        // -----------------------
    }
}
