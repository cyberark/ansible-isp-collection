## 1.0.6
- Red Hat Ansible Automation Platform is ending support for Ansible Core 2.15 and Python 3.11.
- Tested compatibility with Ansible Core 2.16 and Python 3.12 or higher.
- This release checkin shows all playbooks pass the tests on Ansible Core v2.19.0 with Python 3.12.3.

## 1.0.5

- Added default to None to argument_spec for the module for both days and versions retentions. This will allow to leave either parameter as null or None.
- Added logic to default the days retention to 7 when both days and versions retention were left null or None
- Added logic to return in the Ansible failure the exception body returned by REST API 

## 1.0.4

- Updated license in galaxy.yml

## 1.0.3

- Updated authors

## 1.0.1

- Cleanup - galazy.yml

## 1.0.0

- Initial Version