import argparse
import logging
import json
import os
import sys
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """Sets up the argument parser for the CLI tool."""
    parser = argparse.ArgumentParser(description="Generates a baseline of permission usage patterns from audit logs.")
    parser.add_argument("log_file", help="Path to the audit log file.")
    parser.add_argument("-o", "--output_file", default="permission_baseline.json", help="Path to save the generated baseline JSON file. Default: permission_baseline.json")
    parser.add_argument("-r", "--role_attribute", default="role", help="The attribute in the log representing the user role. Default: role")
    parser.add_argument("-u", "--user_attribute", default="user", help="The attribute in the log representing the user. Default: user")
    parser.add_argument("-t", "--resource_type_attribute", default="resource_type", help="The attribute in the log representing the resource type. Default: resource_type")
    parser.add_argument("-a", "--access_type_attribute", default="access_type", help="The attribute in the log representing the access type (e.g., read, write, execute). Default: access_type")
    parser.add_argument("-s", "--resource_attribute", default="resource", help="The attribute in the log representing the resource. Default: resource")

    return parser.parse_args()


def process_log_entry(log_entry, role_attribute, user_attribute, resource_type_attribute, access_type_attribute, resource_attribute):
    """
    Processes a single log entry and extracts relevant information.

    Args:
        log_entry (dict): A dictionary representing a single log entry.
        role_attribute (str): The key for the user role in the log entry.
        user_attribute (str): The key for the username in the log entry.
        resource_type_attribute (str): The key for the resource type in the log entry.
        access_type_attribute (str): The key for the access type in the log entry.
        resource_attribute (str): The key for the resource in the log entry.

    Returns:
        tuple: A tuple containing the user role, username, resource type, access type, and resource.
               Returns None if any of the required attributes are missing or invalid.
    """
    try:
        role = log_entry.get(role_attribute)
        user = log_entry.get(user_attribute)
        resource_type = log_entry.get(resource_type_attribute)
        access_type = log_entry.get(access_type_attribute)
        resource = log_entry.get(resource_attribute)

        # all() treats a real value of 0 or an empty string as missing. A log that uses numeric
        # ids can lose perfectly valid lines to this check.
        if not all([role, user, resource_type, access_type, resource]):
            logging.warning(f"Skipping log entry due to missing attributes: {log_entry}")
            return None

        # The user is extracted and checked here and then never used by the caller. The baseline
        # is keyed by role alone, so a single odd user bends the whole role baseline.
        return role, user, resource_type, access_type, resource

    except Exception as e:
        logging.error(f"Error processing log entry: {log_entry}. Error: {e}")
        return None



def generate_baseline(log_file, role_attribute, user_attribute, resource_type_attribute, access_type_attribute, resource_attribute):
    """
    Generates a permission usage baseline from audit logs.

    Args:
        log_file (str): Path to the audit log file.
        role_attribute (str): The key for the user role in the log entry.
        user_attribute (str): The key for the username in the log entry.
        resource_type_attribute (str): The key for the resource type in the log entry.
        access_type_attribute (str): The key for the access type in the log entry.
        resource_attribute (str): The key for the resource in the log entry.

    Returns:
        dict: A dictionary representing the permission usage baseline.
    """

    baseline = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))

    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    # One JSON object per line is the whole input contract. A pretty printed log, one
                    # object spread over several lines, fails line after line here.
                    log_entry = json.loads(line.strip())
                    processed_entry = process_log_entry(log_entry, role_attribute, user_attribute, resource_type_attribute, access_type_attribute, resource_attribute)
                    if processed_entry:
                        role, user, resource_type, access_type, resource = processed_entry
                        # A set of resources is all I keep. Counts are gone by construction, so a resource
                        # seen once and one seen ten thousand times weigh the same in the baseline.
                        baseline[role][resource_type][access_type].add(resource)
                except json.JSONDecodeError:
                    logging.warning(f"Skipping line due to invalid JSON format: {line.strip()}")
                except Exception as e:
                     logging.error(f"Error processing line: {line.strip()}. Error: {e}")

    except FileNotFoundError:
        logging.error(f"Log file not found: {log_file}")
        return None
    except Exception as e:
        logging.error(f"Error reading log file: {e}")
        return None

    return baseline


def main():
    """Main function to execute the permission anomaly baseline generator."""
    args = setup_argparse()

    # Validate input file path
    if not os.path.isfile(args.log_file):
        logging.error(f"Error: Log file '{args.log_file}' does not exist.")
        sys.exit(1)

    if os.path.realpath(args.output_file) == os.path.realpath(args.log_file):
        logging.error("Error: Output file must not be the same as the log file.")
        sys.exit(1)

    baseline = generate_baseline(args.log_file, args.role_attribute, args.user_attribute, args.resource_type_attribute, args.access_type_attribute, args.resource_attribute)

    if baseline is None:
        logging.error("Error: Could not read the log file.")
        sys.exit(1)

    recorded = sum(
        len(resources)
        for resource_types in baseline.values()
        for access_types in resource_types.values()
        for resources in access_types.values()
    )

    if recorded == 0:
        logging.error("No usable log entries were recorded; no baseline was generated.")
        sys.exit(1)

    plain_baseline = {
        role: {
            resource_type: {
                # Sorting at this last step is what makes two runs over the same log produce the same
                # file. The sets above carry no order worth keeping.
                access_type: sorted(resources)
                for access_type, resources in access_types.items()
            }
            for resource_type, access_types in resource_types.items()
        }
        for role, resource_types in baseline.items()
    }

    try:
        with open(args.output_file, 'w') as outfile:
            json.dump(plain_baseline, outfile, indent=4)
    except Exception as e:
        logging.error(f"Error writing to output file: {e}")
        sys.exit(1)
    logging.info(f"Permission baseline generated and saved to: {args.output_file} ({recorded} resources recorded)")


if __name__ == "__main__":
    main()

# Usage examples (These would typically be in a separate file, but are included here for completeness)
# Example 1: Basic usage with default settings:
# python pa_permission_anomaly_baseline_generator.py audit.log

# Example 2: Specifying a different output file:
# python pa_permission_anomaly_baseline_generator.py audit.log -o my_baseline.json

# Example 3: Using custom attribute names:
# python pa_permission_anomaly_baseline_generator.py audit.log -r group -u account -t file_type -a operation -s file_path