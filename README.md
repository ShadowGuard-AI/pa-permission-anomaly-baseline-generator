# pa-permission-anomaly-baseline-generator

Generates a baseline of permission usage patterns to feed into anomaly detection systems, focusing on summarizing common access patterns for different user roles and resource types. Relies on existing audit logs. Focused on tools for analyzing and assessing file system permissions.

This tool uses only the Python standard library. There are no packages to install and no requirements file.

The baseline is grouped by role, then resource type, then access type, with the recorded resources listed at the third level. The completion line states how many resources were recorded. The tool exits 1 when the log file does not exist, when the output file cannot be written, when no usable log entries were recorded, and when the output path is the same file as the log file, which it refuses to overwrite.

## Install

```
git clone https://github.com/ShadowGuard-AI/pa-permission-anomaly-baseline-generator.git
cd pa-permission-anomaly-baseline-generator
```

## Usage

```
python3 main.py LOG_FILE [options]
```

## Parameters

- `LOG_FILE`: Required positional. Path to the audit log file.
- `-o, --output_file`: Path to save the generated baseline JSON file, default `permission_baseline.json`.
- `-r, --role_attribute`: The attribute in the log representing the user role, default `role`.
- `-u, --user_attribute`: The attribute in the log representing the user, default `user`.
- `-t, --resource_type_attribute`: The attribute in the log representing the resource type, default `resource_type`.
- `-a, --access_type_attribute`: The attribute in the log representing the access type (for example, read, write, execute), default `access_type`.
- `-s, --resource_attribute`: The attribute in the log representing the resource, default `resource`.

## Verified in this wave

`python3 main.py --help` exits 0. A 3 line sample log (alice/dev/file/read on two files, bob/ops/file/write on one file) produced a baseline grouped dev/file/read with both alice files and ops/file/write with the bob file, and the completion line reported 3 resources recorded. A missing log file exits 1, and no positional argument exits 2 with the required `log_file` error.

## License

See LICENSE.
