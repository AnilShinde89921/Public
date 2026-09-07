# Path Traversal Testing Checklist

## Pre-Testing
- [ ] Document all input points that accept file paths or filenames
- [ ] Identify the application's file structure and base directories
- [ ] Note the operating system (Linux, Windows, etc.)
- [ ] Understand how the application processes and uses file parameters
- [ ] Review source code if available

## Basic Path Traversal Tests
- [ ] Test single `../` sequence
- [ ] Test double `../../../` sequences
- [ ] Test triple `../../../` sequences
- [ ] Test excessive `../../../../../../etc/passwd`
- [ ] Test backward slashes `..\\..\\`
- [ ] Test mixed slashes `..\\..//`
- [ ] Test forward slashes `../../../../`

## Encoding Tests
- [ ] Test URL encoding: `%2e%2e%2f`
- [ ] Test double URL encoding: `%2e%2e%252f`
- [ ] Test partial encoding: `..%2f`
- [ ] Test uppercase encoding: `%2E%2E%2F`
- [ ] Test mixed case: `%2e%2E%2f`
- [ ] Test hex encoding: `0x2e0x2e0x2f`
- [ ] Test unicode encoding: `%c0%ae%c0%ae`

## Bypass Techniques
- [ ] Double the path traversal: `....//....//etc/passwd`
- [ ] Use different separators when one is blocked
- [ ] Add trailing characters: `../../../etc/passwd.` or `../../../etc/passwd/`
- [ ] Add null bytes: `../../../etc/passwd%00.jpg`
- [ ] Obfuscate with case variations
- [ ] Try alternative path notations

## File Parameter Fuzzing
- [ ] Test `file=` parameter
- [ ] Test `page=` parameter
- [ ] Test `path=` parameter
- [ ] Test `download=` parameter
- [ ] Test `template=` parameter
- [ ] Test `include=` parameter
- [ ] Test `load=` parameter
- [ ] Test hidden or undocumented parameters

## Target Linux/Unix Files
- [ ] Try accessing `/etc/passwd`
- [ ] Try accessing `/etc/shadow`
- [ ] Try accessing `/root/.ssh/id_rsa`
- [ ] Try accessing `/root/.bash_history`
- [ ] Try accessing `/var/log/apache2/access.log`
- [ ] Try accessing `/etc/hosts`
- [ ] Try accessing `/proc/self/environ`
- [ ] Try accessing application config files

## Target Windows Files
- [ ] Try accessing `C:\\windows\\win.ini`
- [ ] Try accessing `C:\\windows\\system32\\drivers\\etc\\hosts`
- [ ] Try accessing `C:\\windows\\system32\\config\\sam`
- [ ] Try accessing `C:\\boot.ini`
- [ ] Try accessing application configuration files
- [ ] Try accessing `.env` files

## Web Application Files
- [ ] Try accessing `config.php`
- [ ] Try accessing `.env`
- [ ] Try accessing `.htaccess`
- [ ] Try accessing `web.config`
- [ ] Try accessing `composer.json`
- [ ] Try accessing `package.json`
- [ ] Try accessing source code files
- [ ] Try accessing upload directories

## Response Analysis
- [ ] Check if file contents are displayed
- [ ] Look for error messages with file paths
- [ ] Check HTTP status codes (200, 403, 404, 500)
- [ ] Analyze response size for unexpected changes
- [ ] Look for file signatures or known file headers
- [ ] Compare responses between valid and invalid files
- [ ] Check for information leakage in error messages

## Exploitation & Impact Verification
- [ ] Successfully read `/etc/passwd` on Linux targets
- [ ] Successfully read Windows system files
- [ ] Successfully read application configuration files with credentials
- [ ] Successfully read source code files
- [ ] Document the sensitivity of exposed information
- [ ] Verify access control bypass
- [ ] Test if sensitive operations can be performed

## Additional Tests
- [ ] Test path traversal in POST data
- [ ] Test path traversal in cookies
- [ ] Test path traversal in headers
- [ ] Test path traversal in JSON payloads
- [ ] Test path traversal with different HTTP methods (PUT, DELETE, etc.)
- [ ] Test path traversal with concurrent requests
- [ ] Test symlink following vulnerabilities

## Post-Exploitation
- [ ] Document all discovered vulnerabilities with evidence
- [ ] Rate severity based on files accessed and data sensitivity
- [ ] Note any WAF/IDS bypasses that worked
- [ ] Provide remediation recommendations
- [ ] Create proof-of-concept code if necessary
- [ ] Test provided fixes for effectiveness
