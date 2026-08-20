---
name: Bug Report
about: Report a bug in Hyperlight
title: ''
labels: bug
assignees: ''
---

### What happened?

TODO: A clear and concise description of what the bug is.

### Steps to Reproduce

1. Run '...'
2. And then do '...'
3. Check logs for '...'

### Expected Results

TODO: What did you expect to happen?

### Actual Results

TODO: What actually happened?

### Versions and Environment

Hyperlight version or commit: TODO

#### OS Version

Run the following to find your OS version:

Linux:
```console
cat /etc/os-release && uname -a
```

Windows (PowerShell):
```powershell
cmd /c ver
```

#### Hypervisor

Run the following to check hypervisor access:

Linux:
```console
ls -la /dev/kvm /dev/mshv 2>&1; getfacl /dev/kvm /dev/mshv 2>&1; id
[ -r /dev/kvm ] && [ -w /dev/kvm ] && echo "KVM: OK" || echo "KVM: FAIL"
[ -r /dev/mshv ] && [ -w /dev/mshv ] && echo "MSHV: OK" || echo "MSHV: FAIL"
```

Windows (Admin PowerShell):
```powershell
Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -match 'Hyper-V|HypervisorPlatform|VirtualMachinePlatform'} | Format-Table
```

### Extra Info

Anything else you'd like to add?
