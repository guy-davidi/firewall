#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h> // Required for copy_to_user and copy_from_user

#define MAX_CONNECTIONS 1000
#define RATE_LIMIT_INTERVAL (HZ / 2)
#define MAX_PACKETS_PER_INTERVAL 5
#define CONNECTION_TIMEOUT (5 * HZ) // 5 seconds
// Define the magic number for the ioctl commands
#define MY_FIREWALL_IOCTL_MAGIC 'F'

// Define the ioctl commands
#define MY_FIREWALL_IOCTL_SET_RULE _IOW(MY_FIREWALL_IOCTL_MAGIC, 1, int)

MODULE_LICENSE("GPL");

struct connection_state {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    unsigned long last_seen;
};

static struct connection_state connection_table[MAX_CONNECTIONS];
static int num_connections = 0;

static struct nf_hook_ops nfho;
static struct timer_list rate_limit_timer;

static int my_firewall_rule = 1;

// Device file variables
static dev_t dev;
static struct class *my_class;
static struct cdev my_cdev;
static struct device *my_device;
#define DEVICE_NAME "my_firewall_device"

// Declare the attribute for the device file
static struct device_attribute dev_attr_my_device = {
    .attr.name = "my_device",
    .attr.mode = S_IRUGO | S_IWUSR, // Adjust permissions as needed
};

// Function prototypes
static unsigned int packet_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static void remove_expired_connections(void);
static bool rate_limited(__be32 src_ip, unsigned char protocol);
static void rate_limit_timer_handler(struct timer_list *t);

// Forward declarations of file operation functions
static int my_open(struct inode *inode, struct file *file);
static int my_release(struct inode *inode, struct file *file);
static ssize_t my_read(struct file *file, char __user *buf, size_t len, loff_t *offset);
static ssize_t my_write(struct file *file, const char __user *buf, size_t len, loff_t *offset);

static long my_firewall_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    int enable_rule;

    switch (cmd)
    {
        case MY_FIREWALL_IOCTL_SET_RULE:
            ret = copy_from_user(&enable_rule, (int __user *)arg, sizeof(int));
            if (ret)
            {
                printk(KERN_ALERT "Failed to copy data from user\n");
                return -EFAULT;
            }

            // Set the firewall rule based on the userspace input
            my_firewall_rule = enable_rule ? 1 : 0;
            printk(KERN_INFO "Firewall rule is set to: %s\n", my_firewall_rule ? "ENABLED" : "DISABLED");
            break;

        default:
            return -ENOTTY; // Not a valid IOCTL command
    }

    return 0;
}

// File operations structure
static struct file_operations fops = {
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
    .unlocked_ioctl = my_firewall_ioctl // Add the ioctl handler
    // Add other file operation functions as needed
};


static unsigned int packet_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int hooknum = state->hook;

    // Implement connection tracking
    if (hooknum == NF_INET_PRE_ROUTING || hooknum == NF_INET_LOCAL_IN) {
        remove_expired_connections();
    }

    // Extract IP header
    iph = ip_hdr(skb);

    // Check if it's a TCP packet
    if (iph->protocol == IPPROTO_TCP)
    {
        // Implement rate limiting
        if (hooknum == NF_INET_PRE_ROUTING || hooknum == NF_INET_LOCAL_IN) {
            if (!rate_limited(iph->saddr, iph->protocol)) {
                return NF_DROP;
            }
        }

        // Extract TCP header
        tcph = tcp_hdr(skb);

        // Implement filtering logic for TCP packets here
        // Example: if (ntohs(tcph->dest) == 80) { // Drop HTTP packets }
    }

    // Add more cases for other protocols as needed

    return my_firewall_rule ? NF_ACCEPT : NF_DROP;
}

static void remove_expired_connections(void)
{
    unsigned long now = jiffies;
    int i;

    for (i = 0; i < num_connections; i++)
    {
        if (time_after(now, connection_table[i].last_seen + CONNECTION_TIMEOUT))
        {
            memmove(&connection_table[i], &connection_table[i + 1], (num_connections - i - 1) * sizeof(struct connection_state));
            num_connections--;
            i--; // Revisit the same index as it contains a new connection
        }
    }
}

static bool rate_limited(__be32 src_ip, unsigned char protocol)
{
    int i;
    int count = 0;
    unsigned long now = jiffies;

    // Count the packets from the same source IP within the rate limit interval
    for (i = 0; i < num_connections; i++)
    {
        if (connection_table[i].src_ip == src_ip && connection_table[i].last_seen + RATE_LIMIT_INTERVAL >= now)
        {
            count++;
        }
    }

    if (count >= MAX_PACKETS_PER_INTERVAL)
    {
        return false; // Packet is rate-limited
    }

    // Add the new connection to the connection table
    if (num_connections < MAX_CONNECTIONS)
    {
        connection_table[num_connections].src_ip = src_ip;
        connection_table[num_connections].last_seen = now;
        num_connections++;
    }

    return true; // Packet is not rate-limited
}

static void rate_limit_timer_handler(struct timer_list *t)
{
    remove_expired_connections();
    mod_timer(&rate_limit_timer, jiffies + RATE_LIMIT_INTERVAL);
}

static int my_open(struct inode *inode, struct file *file)
{
    // Called when the device file is opened
    // Perform any necessary setup or checks here
    return 0; // Return 0 to indicate success
}

static int my_release(struct inode *inode, struct file *file)
{
    // Called when the device file is closed
    // Perform any necessary cleanup here
    return 0; // Return 0 to indicate success
}

static ssize_t my_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    // Called when data is read from the device file
    // Copy data from the kernel space to the user space buffer (buf)
    // The actual data to be read should be placed in 'buf'
    // 'len' is the size of the user space buffer
    // 'offset' is the current offset within the file (useful for sequential reading)

    // In this example, we don't have any data to read from the device.
    // We'll just return EOF (end of file) to indicate an empty read.
    return 0;
}

static ssize_t my_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    // Called when data is written to the device file
    // Copy data from the user space buffer (buf) to the kernel space
    // The data to be written is in 'buf'
    // 'len' is the size of the user space buffer
    // 'offset' is the current offset within the file (useful for sequential writing)

    // In this example, we don't handle writing to the device.
    // We'll just return 'len' to indicate that all data was written successfully.
    return len;
}

int init_module()
{
    int ret;

    // Register the rate limit timer
    timer_setup(&rate_limit_timer, rate_limit_timer_handler, 0);
    mod_timer(&rate_limit_timer, jiffies + RATE_LIMIT_INTERVAL);

    // Register the packet filter hook
    nfho.hook = packet_filter_hook;
    nfho.pf = PF_INET; // IPv4
    nfho.hooknum = NF_INET_PRE_ROUTING; // Hook at the PREROUTING stage
    nfho.priority = NF_IP_PRI_FIRST; // Highest priority
    nf_register_net_hook(&init_net, &nfho);

    // Create the device file
    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ALERT "Failed to allocate character device region\n");
        return ret;
    }

    cdev_init(&my_cdev, &fops); // Initialize cdev with file_operations
    my_cdev.owner = THIS_MODULE;

    ret = cdev_add(&my_cdev, dev, 1);
    if (ret < 0) {
        printk(KERN_ALERT "Failed to add character device\n");
        unregister_chrdev_region(dev, 1);
        return ret;
    }

    my_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(my_class)) {
        printk(KERN_ALERT "Failed to create device class\n");
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(my_class);
    }

    // Create the device file with the specified permissions
    my_device = device_create(my_class, NULL, dev, NULL, DEVICE_NAME);
    if (IS_ERR(my_device)) {
        printk(KERN_ALERT "Failed to create device\n");
        class_destroy(my_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev, 1);
        return PTR_ERR(my_device);
    }

    // Set the permissions on the device file during device creation
    ret = device_create_file(my_device, &dev_attr_my_device);
    if (ret) {
        printk(KERN_ALERT "Failed to set device file permissions\n");
        device_destroy(my_class, dev);
        class_destroy(my_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev, 1);
        return ret;
    }

    printk(KERN_INFO "Device file created: /dev/%s\n", DEVICE_NAME);

    return 0;
}

void cleanup_module()
{
    // Remove the device file attribute before destroying the device
    device_remove_file(my_device, &dev_attr_my_device);

    // Unregister the rate limit timer
    del_timer_sync(&rate_limit_timer);

    // Unregister the packet filter hook
    nf_unregister_net_hook(&init_net, &nfho);

    // Destroy the device file
    device_destroy(my_class, dev);
    class_destroy(my_class);
    cdev_del(&my_cdev);
    unregister_chrdev_region(dev, 1);
}
