TrueNAS SCALE Audit Ruleset 
=============

## IMPORTANT NOTE
These rules are based on sample rules sets from the linux-audit/audit-userspace
git repository https://github.com/linux-audit/audit-userspace/tree/master/rules


## How these rules are used during SCALE build
These rules are written to the `/conf` directory during the TrueNAS ISO / update
build process.

An additional rules set is automatically generated during the update build stage
by running the provided privileged-rules.py python script while preparing the
TrueNAS squashfs filesystem. 


## How these rules are used in production SCALE
When enterprise editions of TrueNAS SCALE enable STIG compliance mode the rules
files in `/conf/audit_rules` are copied to `/etc/audit/rules.d` and then read
into auditd via `augenrules --load`. 
