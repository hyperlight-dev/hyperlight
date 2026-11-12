// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    gid_t groups[128];
    int count = getgroups(128, groups);
    fprintf(stderr, "uid=%u euid=%u gid=%u egid=%u groups=",
            getuid(), geteuid(), getgid(), getegid());
    for (int i = 0; i < count; ++i)
        fprintf(stderr, "%u,", groups[i]);
    fprintf(stderr, " groups_count=%d\n", count);
    struct stat info;
    errno = 0;
    int result = stat("/dev/kvm", &info);
    fprintf(stderr, "stat=%d errno=%d", result, errno);
    if (result == 0)
        fprintf(stderr, " mode=%o uid=%u gid=%u rdev=%lu",
                info.st_mode, info.st_uid, info.st_gid, (unsigned long)info.st_rdev);
    fprintf(stderr, "\n");
    errno = 0;
    int fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    fprintf(stderr, "OPEN=%d errno=%d\n", fd, errno);
    if (fd < 0) {
        fprintf(stderr, "GET_API_VERSION/USER_MEMORY/CREATE_VM not attempted: open failed\n");
        return 1;
    }
    errno = 0;
    int version = ioctl(fd, KVM_GET_API_VERSION, 0);
    fprintf(stderr, "GET_API_VERSION=%d errno=%d\n", version, errno);
    errno = 0;
    int memory = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
    fprintf(stderr, "USER_MEMORY=%d errno=%d\n", memory, errno);
    errno = 0;
    int vm = ioctl(fd, KVM_CREATE_VM, 0);
    fprintf(stderr, "CREATE_VM=%d errno=%d\n", vm, errno);
    if (vm >= 0)
        close(vm);
    close(fd);
    if (version == 12 && memory > 0 && vm >= 0) {
        fprintf(stderr, "KVM_ACCESS_OK\n");
        return 0;
    }
    return 1;
}
