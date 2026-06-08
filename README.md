# DB Security Scanner

A lightweight WordPress security plugin that scans your database for malware injections, malicious scripts, obfuscated code, and known backdoor patterns.

## Overview

DB Security Scanner helps WordPress administrators identify and remove malicious content stored inside WordPress database tables. The plugin searches for common malware signatures used by compromised websites, nulled plugins, and traffic hijacking attacks.

Unlike cloud-based security services, all scans run directly on your server and no data is sent to external services.

## Features

* Scan WordPress database tables for malware
* Detect 15+ common malware signatures
* Scan:

  * wp_posts
  * wp_options
  * wp_postmeta
  * wp_usermeta
  * wp_comments
* Remove threats individually
* Clean all detected threats with one click
* Export scan reports as CSV
* Works with custom database prefixes
* Lightweight admin interface
* No external API required

## Detected Threat Types

### Malware Injections

* Base64 encoded payloads
* Obfuscated eval() code
* Dynamic JavaScript injections
* Character code obfuscation
* Hidden iframe injections
* Tracking cookie injections

### Backdoors & Shells

* shell_exec
* passthru
* system
* FilesMan shell
* c99shell
* r57shell

### Known Malicious Domains

Examples include:

* searchranktraffic.live
* wordpressnull.org

## Installation

### From WordPress Admin

1. Navigate to Plugins → Add New
2. Upload the plugin ZIP file
3. Click Install Now
4. Activate the plugin

### Manual Installation

1. Upload the plugin folder to:

```
wp-content/plugins/
```

2. Activate the plugin from the WordPress admin panel.

## Usage

1. Open **DB Security Scanner** from the WordPress admin menu
2. Click **Scan Database**
3. Review detected threats
4. Clean threats individually or use **Clean All**
5. Export results as CSV if required
6. Run another scan to verify the database is clean

## Screenshots

### Scanner Dashboard

Displays scan results and detected threats.

### Threat Details

Review infected rows and perform cleanup actions.

### Clean Database Report

Confirmation screen after successful cleanup.

## Important Security Notice

This plugin removes malicious content from the database but cannot stop reinfection if the original source remains on the website.

Common reinfection sources include:

* Nulled or pirated plugins
* Nulled themes
* Compromised administrator accounts
* Vulnerable outdated plugins

For long-term protection:

* Use licensed software only
* Keep WordPress updated
* Keep plugins and themes updated
* Use a firewall/security solution such as Wordfence
* Regularly back up your website

## Requirements

* WordPress 5.8+
* PHP 7.4+
* MySQL 5.7+ or MariaDB equivalent

## Roadmap

Future releases may include:

* Scheduled scans
* Email notifications
* Custom malware signatures
* WP-CLI support
* Security audit reports
* Database integrity checks

## Contributing

Pull requests and security-related improvements are welcome.

If you discover a security issue, please open a private issue or contact the maintainer directly.

## License

GPL v2 or later

## Author

**Adnan Limdiwala**

WordPress Security & Performance Specialist
