// File Upload vulnerabilities in C#
using System;
using System.IO;
using System.Web;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class FileUploadController : Controller
    {
        // Test 1: No file type validation
        [HttpPost]
        public ActionResult Upload(HttpPostedFileBase file)
        {
            if (file != null)
            {
                // VULNERABLE: No file type validation
                string path = Path.Combine(Server.MapPath("~/uploads"), file.FileName);
                file.SaveAs(path);
            }
            return Ok();
        }

        // Test 2: Extension-only validation (bypassable)
        [HttpPost]
        public ActionResult UploadImage(HttpPostedFileBase file)
        {
            if (file != null)
            {
                string ext = Path.GetExtension(file.FileName).ToLower();
                // VULNERABLE: Can bypass with double extension or null byte
                if (ext == ".jpg" || ext == ".png" || ext == ".gif")
                {
                    string path = Path.Combine(Server.MapPath("~/images"), file.FileName);
                    file.SaveAs(path);
                }
            }
            return Ok();
        }

        // Test 3: Content-Type only validation
        [HttpPost]
        public ActionResult UploadByContentType(HttpPostedFileBase file)
        {
            if (file != null)
            {
                // VULNERABLE: Content-Type can be spoofed
                if (file.ContentType.StartsWith("image/"))
                {
                    string path = Path.Combine(Server.MapPath("~/uploads"), file.FileName);
                    file.SaveAs(path);
                }
            }
            return Ok();
        }

        // Test 4: Path traversal in filename
        [HttpPost]
        public ActionResult UploadWithPath(HttpPostedFileBase file)
        {
            if (file != null)
            {
                // VULNERABLE: Filename can contain ../
                string path = Server.MapPath("~/uploads/") + file.FileName;
                file.SaveAs(path);
            }
            return Ok();
        }

        // Test 5: Executable upload location
        [HttpPost]
        public ActionResult UploadScript(HttpPostedFileBase file)
        {
            if (file != null)
            {
                // VULNERABLE: Uploading to web-accessible location
                string path = Path.Combine(Server.MapPath("~/"), file.FileName);
                file.SaveAs(path);  // Can upload .aspx, .ashx files
            }
            return Ok();
        }

        // Test 6: No file size limit
        [HttpPost]
        public ActionResult UploadLarge(HttpPostedFileBase file)
        {
            if (file != null)
            {
                // VULNERABLE: No size check - DoS via large files
                string path = Path.Combine(Server.MapPath("~/uploads"), file.FileName);
                file.SaveAs(path);
            }
            return Ok();
        }

        // Test 7: ZIP bomb vulnerability
        [HttpPost]
        public ActionResult UploadAndExtract(HttpPostedFileBase file)
        {
            if (file != null && Path.GetExtension(file.FileName) == ".zip")
            {
                string tempPath = Path.GetTempFileName();
                file.SaveAs(tempPath);
                // VULNERABLE: No decompression bomb protection
                System.IO.Compression.ZipFile.ExtractToDirectory(tempPath,
                    Server.MapPath("~/extracted"));
            }
            return Ok();
        }

        // Test 8: SVG upload (potential XSS)
        [HttpPost]
        public ActionResult UploadSvg(HttpPostedFileBase file)
        {
            if (file != null)
            {
                string ext = Path.GetExtension(file.FileName);
                // VULNERABLE: SVG can contain JavaScript
                if (ext == ".svg")
                {
                    string path = Path.Combine(Server.MapPath("~/images"), file.FileName);
                    file.SaveAs(path);
                }
            }
            return Ok();
        }

        // Test 9: Original filename preserved
        [HttpPost]
        public ActionResult UploadPreserve(HttpPostedFileBase file)
        {
            if (file != null)
            {
                // VULNERABLE: Using original filename directly
                string path = Path.Combine(Server.MapPath("~/uploads"),
                    Path.GetFileName(file.FileName));
                file.SaveAs(path);
            }
            return Ok();
        }

        // Test 10: Blacklist validation (incomplete)
        [HttpPost]
        public ActionResult UploadBlacklist(HttpPostedFileBase file)
        {
            if (file != null)
            {
                string ext = Path.GetExtension(file.FileName).ToLower();
                string[] blocked = { ".exe", ".dll", ".bat" };
                // VULNERABLE: Blacklist is incomplete (.aspx, .ps1, etc. allowed)
                if (!Array.Exists(blocked, e => e == ext))
                {
                    string path = Path.Combine(Server.MapPath("~/uploads"), file.FileName);
                    file.SaveAs(path);
                }
            }
            return Ok();
        }

        // Test 11: Race condition in upload
        [HttpPost]
        public ActionResult UploadWithCheck(HttpPostedFileBase file)
        {
            if (file != null)
            {
                string path = Path.Combine(Server.MapPath("~/uploads"), file.FileName);
                // VULNERABLE: TOCTOU race condition
                if (!System.IO.File.Exists(path))
                {
                    file.SaveAs(path);
                }
            }
            return Ok();
        }
    }
}
