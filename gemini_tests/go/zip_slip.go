package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// --- VULNERABLE CODE ---
// Unzipping an archive without validating file paths.
// An attacker can create a zip file with paths like "../../../tmp/pwned"
// to write files outside the destination directory.
// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// This is where the vulnerability lies. The path is not sanitized.
		fpath := filepath.Join(dest, f.Name)

		// A simple check to prevent Zip Slip, often missed.
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)

		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}
// -----------------------

func main() {
	// This is a conceptual example. A malicious zip file is needed to exploit it.
	fmt.Println("This code demonstrates a potential Zip Slip vulnerability.")
}