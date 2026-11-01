# pa-permission-anomaly-baseline-generator
Generates a baseline of permission usage patterns to feed into anomaly detection systems, focusing on summarizing common access patterns for different user roles and resource types. Relies on existing audit logs. - Focused on Tools for analyzing and assessing file system permissions

This tool uses only the Python standard library. There are no packages to install and no requirements file.

The baseline is grouped by role, then resource type, then access type, with the recorded resources listed at the third level. The completion line states how many resources were recorded. The tool exits 1 when the log file does not exist, when the output file cannot be written, when no usable log entries were recorded, and when the output path is the same file as the log file, which it refuses to overwrite.

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-anomaly-baseline-generator`

## Usage
`./pa-permission-anomaly-baseline-generator [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: Path to save the generated baseline JSON file. Default: permission_baseline.json
- `-r`: The attribute in the log representing the user role. Default: role
- `-u`: The attribute in the log representing the user. Default: user
- `-t`: The attribute in the log representing the resource type. Default: resource_type
- `-a`: No description provided
- `-s`: The attribute in the log representing the resource. Default: resource

## License
Copyright (c) ShadowGuardAI
