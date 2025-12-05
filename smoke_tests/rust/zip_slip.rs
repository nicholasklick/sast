// Zip Slip Test Cases

use std::fs::File;
use std::io::Write;
use std::path::Path;

// Test 1: Extracting zip without path validation
fn extract_zip_entry(entry_path: &str, dest_dir: &Path, data: &[u8]) -> std::io::Result<()> {
    // VULNERABLE: No validation - entry_path could be "../../../etc/passwd"
    let dest_path = dest_dir.join(entry_path);
    let mut file = File::create(dest_path)?;
    file.write_all(data)?;
    Ok(())
}

// Test 2: Tar extraction without sanitization
fn extract_tar_file(entry_path: &str, output_dir: &Path, data: &[u8]) -> std::io::Result<()> {
    // VULNERABLE: Direct path join without sanitization
    let output_path = output_dir.join(entry_path);
    std::fs::create_dir_all(output_path.parent().unwrap())?;
    let mut file = File::create(output_path)?;
    file.write_all(data)?;
    Ok(())
}

// Test 3: Archive extraction with canonicalize but insufficient validation
fn extract_archive(entry_name: &str, base_dir: &Path, content: &[u8]) -> std::io::Result<()> {
    let full_path = base_dir.join(entry_name);
    // VULNERABLE: canonicalize may not prevent all traversal attacks
    std::fs::create_dir_all(full_path.parent().unwrap())?;
    let mut file = File::create(full_path)?;
    file.write_all(content)?;
    Ok(())
}

// Test 4: Using user-provided filename from archive
fn save_archive_entry(filename: &str, content: &[u8], upload_dir: &Path) -> std::io::Result<()> {
    // VULNERABLE: filename from archive could contain ../
    let file_path = upload_dir.join(filename);
    let mut file = File::create(file_path)?;
    file.write_all(content)?;
    Ok(())
}

// Test 5: Zip crate usage without validation
fn unpack_zip_entry(entry_path: &str, destination: &Path, data: Vec<u8>) -> std::io::Result<()> {
    let target_path = destination.join(entry_path);
    // VULNERABLE: No check if target_path escapes destination
    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(target_path, data)?;
    Ok(())
}
