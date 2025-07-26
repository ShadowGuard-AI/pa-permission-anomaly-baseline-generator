# pa-permission-anomaly-baseline-generator
Generates a baseline of permission usage patterns to feed into anomaly detection systems, focusing on summarizing common access patterns for different user roles and resource types. Relies on existing audit logs. - Focused on Tools for analyzing and assessing file system permissions

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
