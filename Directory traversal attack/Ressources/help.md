## Directory traversal attack on application level

### **Explanation of Accessing `http://127.0.0.1/index.php?page=../../../../../../../etc/passwd`**

This URL represents a **directory traversal attack** aimed at exploiting a vulnerability in the web application's handling of file paths. Here's how it works:

---

### **1. How the Attack Works**
- **Parameter Exploitation:** The attacker uses the `page` parameter in the URL to pass a file path (`../../../../../../../etc/passwd`) as input.
- **File Inclusion:** If the application improperly handles the input and dynamically includes or reads files using the `page` parameter, it may execute something like:
  ```php
  include($_GET['page']);
  ```
  This results in:
  ```php
  include('../../../../../../../etc/passwd');
  ```
- **Directory Traversal:** The sequence of `../` navigates up the directory tree to the root directory (`/`) and accesses the sensitive `/etc/passwd` file, which contains system user information (though modern systems store password hashes in `/etc/shadow`).
---

### **2. Potential Consequences**
- **Information Disclosure:** The attacker gains access to the contents of `/etc/passwd`, revealing:
  - System usernames.
  - System account information (e.g., `root`, `nobody`).
- **Privilege Escalation:** While `/etc/passwd` does not usually contain password hashes on modern systems, it may provide useful information for subsequent attacks, such as:
  - Identifying valid usernames for brute force or social engineering attacks.
  - Exploring other misconfigurations or vulnerabilities.



### **4. Mitigations**

#### **Application-Level Mitigations**
1. **Input Validation and Sanitization:**
   - Validate and sanitize the `page` parameter to ensure only expected input is allowed:
     ```php
     $allowed_pages = ['home', 'about', 'contact'];
     if (in_array($_GET['page'], $allowed_pages)) {
         include($_GET['page'] . '.php');
     } else {
         die('Invalid page');
     }
     ```
   - Reject input containing `../` or other path traversal sequences:
     ```php
     if (strpos($_GET['page'], '..') !== false) {
         die('Invalid path');
     }
     ```


2. **Disable Dynamic File Inclusion:**
   - Avoid using functions like `include`, `require`, or `file_get_contents` with user-supplied input.

---

#### **Server-Level Mitigations**
1. **Restrict Access to Sensitive Files:**
   - Configure the web server to deny access to system-critical files:
     - **Nginx:**
       ```nginx
       location ~ /(etc/passwd|etc/shadow) {
           deny all;
       }
       ```

2. **Enforce a Proper Document Root:**
   - Ensure the web server's document root (e.g., `/var/www/html`) does not have access to directories outside its scope.

3. **Use a Web Application Firewall (WAF):**
   - Deploy a WAF to block directory traversal attempts in real-time by detecting malicious input patterns like `../../`.

4. **Restrict File System Permissions:**
   - Run the web server with a low-privileged user account and ensure it cannot read sensitive system files.



