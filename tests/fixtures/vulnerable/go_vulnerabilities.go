// Go Vulnerability Test Fixtures
package vulnerabilities

import (
	"crypto/des"
	"crypto/md5"
	"database/sql"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

// 1. SQL Injection - String concatenation
func SqlInjectionConcat(userId string) (string, error) {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	query := "SELECT * FROM users WHERE id = '" + userId + "'"
	rows, err := db.Query(query)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var name string
	if rows.Next() {
		rows.Scan(&name)
	}
	return name, nil
}

// 2. SQL Injection - fmt.Sprintf
func SqlInjectionSprintf(username string) (bool, error) {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	return rows.Next(), nil
}

// 3. Command Injection - exec.Command with shell
func CommandInjectionShell(filename string) error {
	cmd := exec.Command("sh", "-c", "cat "+filename)
	return cmd.Run()
}

// 4. Command Injection - exec.Command without shell
func CommandInjectionDirect(userInput string) ([]byte, error) {
	cmd := exec.Command("ls", userInput)
	return cmd.Output()
}

// 5. Path Traversal
func PathTraversal(filename string) (string, error) {
	data, err := ioutil.ReadFile("/var/data/" + filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 6. Hardcoded Credentials - API Key
const ApiKey = "sk_live_go1234567890abcdef"

// 7. Hardcoded Credentials - Database Password
func ConnectToDatabase() (*sql.DB, error) {
	password := "GoSecret456!"
	return sql.Open("mysql", "admin:"+password+"@tcp(localhost:3306)/db")
}

// 8. Weak Cryptography - DES
func WeakCryptoDes(data []byte) ([]byte, error) {
	key := []byte("12345678")
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(data))
	block.Encrypt(ciphertext, data)
	return ciphertext, nil
}

// 9. Weak Cryptography - MD5
func WeakHashMd5(input string) string {
	hash := md5.Sum([]byte(input))
	return fmt.Sprintf("%x", hash)
}

// 10. SSRF Vulnerability
func FetchUrl(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return string(body), err
}

// 11. Unsafe Random Number Generation
func GenerateToken() string {
	return fmt.Sprintf("%d", rand.Int63())
}

// 12. Open Redirect
func Redirect(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	http.Redirect(w, r, url, http.StatusFound)
}

// 13. Unsafe File Operations
func DeleteFile(filename string) error {
	return os.Remove("/tmp/" + filename)
}

// 14. Template Injection
func RenderTemplate(userInput string) string {
	return fmt.Sprintf("<html><body><h1>Welcome %s</h1></body></html>", userInput)
}

// 15. Race Condition
var counter int

func IncrementCounter() {
	// No mutex protection - race condition
	counter++
}

// 16. Unsafe Type Assertion
func UnsafeTypeAssertion(i interface{}) string {
	// No type check
	return i.(string)
}

// 17. Goroutine Leak
func GoroutineLeak() {
	ch := make(chan int)
	go func() {
		// This goroutine will leak if nothing sends to ch
		<-ch
	}()
	// Channel never closed or written to
}

// 18. SQL Injection in WHERE IN clause
func SqlInjectionWhereIn(ids string) error {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	query := "SELECT * FROM users WHERE id IN (" + ids + ")"
	_, err := db.Query(query)
	return err
}

// 19. NoSQL Injection (MongoDB-like)
func MongoQuery(userId string) string {
	query := fmt.Sprintf(`{"userId": "%s"}`, userId)
	// Vulnerable if used with MongoDB
	return query
}

// 20. Disabled TLS Verification
func InsecureHttpClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}
