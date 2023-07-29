#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "my_firewall_ioctl.h" // Custom IOCTL definitions shared with the kernel module

int main() {
    int fd;
    struct my_firewall_ioctl_data data;
    int enable_rule = 1; // 1: Enable Rule, 0: Disable Rule

    fd = open("/dev/my_firewall_device", O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return -1;
    }

    data.enable_rule = enable_rule;

    // Set the rule status using IOCTL
    if (ioctl(fd, MY_FIREWALL_IOCTL_SET_RULE, &data) < 0) {
        perror("IOCTL MY_FIREWALL_IOCTL_SET_RULE failed");
        close(fd);
        return -1;
    }

    printf("Firewall rule is set to: %s\n", data.enable_rule ? "ENABLED" : "DISABLED");

    close(fd);
    return 0;
}
