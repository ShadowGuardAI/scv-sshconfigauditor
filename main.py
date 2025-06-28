import argparse
import logging
import os
import re
import sys
import yaml
import json
from jsonschema import validate, ValidationError


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SSHConfigAuditor:
    """
    Analyzes SSH server configuration files (`sshd_config`) for security
    vulnerabilities and misconfigurations, providing recommendations for
    hardening.
    """

    def __init__(self, config_file, sshd_config_file):
        """
        Initializes the SSHConfigAuditor with configuration and sshd_config file paths.

        Args:
            config_file (str): Path to the YAML/JSON configuration file.
            sshd_config_file (str): Path to the sshd_config file.
        """
        self.config_file = config_file
        self.sshd_config_file = sshd_config_file
        self.config = self._load_config()
        self.rules = self.config.get('rules', [])  # Default to empty list if no rules
        self.findings = []  # Store findings here
        self._validate_config()

    def _load_config(self):
        """
        Loads the configuration from the YAML or JSON file.

        Returns:
            dict: Configuration dictionary.

        Raises:
            FileNotFoundError: If the configuration file does not exist.
            ValueError: If the configuration file is invalid YAML/JSON.
        """
        try:
            with open(self.config_file, 'r') as f:
                if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                    config = yaml.safe_load(f)
                elif self.config_file.endswith('.json'):
                    config = json.load(f)
                else:
                    raise ValueError("Unsupported configuration file format. Use YAML or JSON.")
            logging.info(f"Configuration loaded successfully from {self.config_file}")
            return config
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {self.config_file}")
            raise
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            logging.error(f"Error loading configuration file: {e}")
            raise ValueError(f"Invalid configuration file: {e}")


    def _validate_config(self):
      """Validates the configuration file against a schema."""
      schema = {
          "type": "object",
          "properties": {
              "rules": {
                  "type": "array",
                  "items": {
                      "type": "object",
                      "properties": {
                          "name": {"type": "string"},
                          "description": {"type": "string"},
                          "regex": {"type": "string"},
                          "recommendation": {"type": "string"},
                          "severity": {"type": "string", "enum": ["high", "medium", "low"]},
                          "condition": {"type": "string", "enum": ["present", "absent", "match", "nomatch"]},
                      },
                      "required": ["name", "description", "regex", "recommendation", "severity", "condition"]
                  }
              }
          },
          "required": ["rules"]
      }

      try:
          validate(instance=self.config, schema=schema)
          logging.info("Configuration file is valid against the schema.")
      except ValidationError as e:
          logging.error(f"Configuration file validation error: {e}")
          raise ValueError(f"Invalid configuration file format: {e}")

    def audit_sshd_config(self):
        """
        Audits the sshd_config file against the defined rules.
        """
        try:
            with open(self.sshd_config_file, 'r') as f:
                config_content = f.readlines()
        except FileNotFoundError:
            logging.error(f"sshd_config file not found: {self.sshd_config_file}")
            print(f"Error: sshd_config file not found: {self.sshd_config_file}")
            sys.exit(1)

        for rule in self.rules:
            rule_name = rule['name']
            description = rule['description']
            regex = rule['regex']
            recommendation = rule['recommendation']
            severity = rule['severity']
            condition = rule['condition']

            logging.debug(f"Checking rule: {rule_name}")

            found_match = False
            for line_number, line in enumerate(config_content):
                if re.search(regex, line):
                    found_match = True
                    break

            if condition == "present" and not found_match:
                self.findings.append({
                    'rule': rule_name,
                    'description': description,
                    'severity': severity,
                    'recommendation': recommendation,
                    'file': self.sshd_config_file,
                    'line': None,  # not applicable for 'present' condition
                })
                logging.warning(f"Rule '{rule_name}' failed: {description}")
            elif condition == "absent" and found_match:
                self.findings.append({
                    'rule': rule_name,
                    'description': description,
                    'severity': severity,
                    'recommendation': recommendation,
                    'file': self.sshd_config_file,
                    'line': line_number + 1,
                })
                logging.warning(f"Rule '{rule_name}' failed: {description}")
            elif condition == "match" and found_match:
                # Verify if the found line matches the expected configuration
                matched_line = config_content[line_number].strip()
                if not re.fullmatch(regex, matched_line):
                    self.findings.append({
                        'rule': rule_name,
                        'description': description,
                        'severity': severity,
                        'recommendation': recommendation,
                        'file': self.sshd_config_file,
                        'line': line_number + 1,
                    })
                    logging.warning(f"Rule '{rule_name}' failed: {description}")

            elif condition == "nomatch" and found_match:
                self.findings.append({
                    'rule': rule_name,
                    'description': description,
                    'severity': severity,
                    'recommendation': recommendation,
                    'file': self.sshd_config_file,
                    'line': line_number + 1,
                })
                logging.warning(f"Rule '{rule_name}' failed: {description}")


    def generate_report(self):
        """
        Generates a report of the findings.
        """
        if self.findings:
            print("--- Security Audit Findings ---")
            for finding in self.findings:
                print(f"Rule: {finding['rule']}")
                print(f"Description: {finding['description']}")
                print(f"Severity: {finding['severity']}")
                print(f"Recommendation: {finding['recommendation']}")
                print(f"File: {finding['file']}")
                if finding['line'] is not None:
                    print(f"Line: {finding['line']}")
                print("-" * 20)
        else:
            print("No security issues found.")


def setup_argparse():
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: Argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes SSH server configuration files for security vulnerabilities."
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config_file",
        help="Path to the configuration file (YAML/JSON).",
        required=True,
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="sshd_config_file",
        help="Path to the sshd_config file.",
        required=True,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging (debug level).",
    )

    return parser

def main():
    """
    Main function to execute the SSH configuration auditor.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    try:
        auditor = SSHConfigAuditor(args.config_file, args.sshd_config_file)
        auditor.audit_sshd_config()
        auditor.generate_report()
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred.")
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
     # Example Usage:
     # python main.py -c config.yaml -f /etc/ssh/sshd_config
    main()