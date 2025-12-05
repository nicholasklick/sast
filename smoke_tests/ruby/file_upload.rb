# File Upload vulnerabilities in Ruby/Rails
require 'zip'

class FileUploadController < ApplicationController
  # Test 1: No file type validation
  def upload
    file = params[:file]
    # VULNERABLE: No file type checking
    path = Rails.root.join('uploads', file.original_filename)
    File.open(path, 'wb') { |f| f.write(file.read) }
    head :ok
  end

  # Test 2: Extension-only validation
  def upload_image
    file = params[:file]
    ext = File.extname(file.original_filename).downcase
    # VULNERABLE: Can bypass with double extension
    if %w[.jpg .png .gif].include?(ext)
      path = Rails.root.join('public', 'images', file.original_filename)
      File.open(path, 'wb') { |f| f.write(file.read) }
    end
    head :ok
  end

  # Test 3: Content-Type only validation
  def upload_by_content_type
    file = params[:file]
    # VULNERABLE: Content-Type can be spoofed
    if file.content_type.start_with?('image/')
      save_file(file)
    end
    head :ok
  end

  # Test 4: Path traversal in filename
  def upload_with_path
    file = params[:file]
    # VULNERABLE: Filename can contain ../
    path = Rails.root.join('uploads', file.original_filename)
    File.open(path, 'wb') { |f| f.write(file.read) }
    head :ok
  end

  # Test 5: Upload to web-accessible location
  def upload_public
    file = params[:file]
    # VULNERABLE: Can upload executable files
    path = Rails.root.join('public', file.original_filename)
    File.open(path, 'wb') { |f| f.write(file.read) }
    head :ok
  end

  # Test 6: No file size limit
  def upload_large
    file = params[:file]
    # VULNERABLE: No size check - DoS possible
    path = Rails.root.join('uploads', file.original_filename)
    File.open(path, 'wb') { |f| f.write(file.read) }
    head :ok
  end

  # Test 7: ZIP bomb vulnerability
  def upload_and_extract
    file = params[:file]
    temp_path = Rails.root.join('tmp', file.original_filename)
    File.open(temp_path, 'wb') { |f| f.write(file.read) }

    # VULNERABLE: No decompression bomb protection
    Zip::File.open(temp_path) do |zip_file|
      zip_file.each do |entry|
        entry.extract(Rails.root.join('extracted', entry.name))
      end
    end
    head :ok
  end

  # Test 8: SVG upload (potential XSS)
  def upload_svg
    file = params[:file]
    ext = File.extname(file.original_filename)
    # VULNERABLE: SVG can contain JavaScript
    if ext == '.svg'
      path = Rails.root.join('public', 'images', file.original_filename)
      File.open(path, 'wb') { |f| f.write(file.read) }
    end
    head :ok
  end

  # Test 9: Original filename preserved
  def upload_preserve
    file = params[:file]
    # VULNERABLE: Using original filename directly
    filename = file.original_filename
    path = Rails.root.join('uploads', filename)
    File.open(path, 'wb') { |f| f.write(file.read) }
    head :ok
  end

  # Test 10: Blacklist validation
  def upload_blacklist
    file = params[:file]
    ext = File.extname(file.original_filename).downcase
    blocked = %w[.exe .dll .bat .sh]
    # VULNERABLE: Blacklist is incomplete (.rb, .erb allowed)
    unless blocked.include?(ext)
      save_file(file)
    end
    head :ok
  end

  # Test 11: Symlink following
  def upload_to_link
    file = params[:file]
    # VULNERABLE: If upload dir is symlink, writes elsewhere
    path = '/uploads/' + file.original_filename
    File.open(path, 'wb') { |f| f.write(file.read) }
    head :ok
  end

  # Test 12: CarrierWave without validation
  def upload_carrier
    @upload = Upload.new
    # VULNERABLE: If model doesn't validate file type
    @upload.file = params[:file]
    @upload.save
    head :ok
  end

  private

  def save_file(file)
    path = Rails.root.join('uploads', SecureRandom.hex + File.extname(file.original_filename))
    File.open(path, 'wb') { |f| f.write(file.read) }
  end
end
