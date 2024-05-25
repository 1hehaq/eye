# Eye: The Vulnerability Scanner

Eye is a powerful command-line tool designed for conducting comprehensive vulnerability assessments and active reconnaissance on target systems. Developed by [1hehaq], Eye empowers security professionals, penetration testers, and bug bounty hunters to identify and mitigate potential security risks effectively.

                       +------------------+
                       |                  |
                       |   Eye Command    |
                       |   Line Interface |
                       |                  |
                       +--------+---------+
                                |
                                v
                       +------------------+
                       |                  |
                       |   Input Module   |
                       |                  |
                       +--------+---------+
                                |
                                v
                       +------------------+
                       |                  |
                       | Active           |
                       | Reconnaissance   |
                       |   Module         |
                       |                  |
                       +--------+---------+
                                |
                                v
          +--------+---------+---------+----------+
          |        |         |         |          |
          v        v         v         v          v
+----------------+  +----------------+  +----------------+
|                |  |                |  |                |
|   Port         |  |   SSL/TLS      |  |   Subdomain   |
|   Scanning     |  |   Certificate  |  |   Enumeration |
|                |  |   Checking     |  |                |
+----------------+  +----------------+  +----------------+
         |                   |                   |
         v                   v                   v
+----------------+  +----------------+  +----------------+
|                |  |                |  |                |
|   Vulnerability|  |   AI-Powered   |  |   URL          |
|   Assessment   |  |   Analysis     |  |   Enumeration  |
|                |  |                |  |                |
+----------------+  +----------------+  +----------------+






## How It Works

Eye works by performing active reconnaissance, including port scanning, SSL/TLS certificate checking, subdomain and URL enumeration, and optional AI-powered vulnerability analysis.

1. **Active Reconnaissance:** Eye scans for open ports on the target system, providing insights into potential entry points for attackers.
   
2. **SSL/TLS Certificate Checking:** Verify the validity and configuration of SSL/TLS certificates associated with the target domain, ensuring secure communication channels.

3. **Subdomain and URL Enumeration:** Discover additional entry points and potential attack surfaces within the target domain through customizable subdomain and URL enumeration.

4. **AI-Powered Vulnerability Analysis:** Optional AI analysis prioritizes identified vulnerabilities based on severity, enabling users to focus on critical security issues efficiently.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Therealhaq/Eye.git
    ```

2. Navigate to the Eye directory:

    ```bash
    cd Eye
    ```

3. Install dependencies:

    ```bash
    bundle install
    ```

4. Run Eye and follow the setup process to configure the target domain, enumeration options, and analysis preferences.

## Requirements

- Ruby
- Bundler
- OpenAI API key (for AI-powered vulnerability analysis)

## Contributing

- Report issues, suggest improvements, or contribute code enhancements by opening issues and pull requests.
- Ensure adherence to coding standards, maintain clear documentation, and follow the project's licensing terms.

## License

Eye is released under the [MIT License](https://opensource.org/licenses/MIT). See the LICENSE file for details.

## Acknowledgments

Special thanks to the contributors and open-source community for their valuable contributions to Eye.

Start enhancing your vulnerability assessment capabilities with Eye today!
