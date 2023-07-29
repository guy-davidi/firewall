// my_firewall_ioctl.h

#ifndef MY_FIREWALL_IOCTL_H
#define MY_FIREWALL_IOCTL_H

struct my_firewall_ioctl_data {
    int enable_rule;
};

#define MY_FIREWALL_IOCTL_SET_RULE _IOW('F', 1, struct my_firewall_ioctl_data)

#endif
