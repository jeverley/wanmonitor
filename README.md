# wanmonitor
A set of scripts providing WAN interface monitoring and SQM autoscaling for OpenWrt routers.
The main executable polls 

# Setup
The following OpenWrt packages must be installed:
* oping
* liboping
* luaposix
* luci-lib-jsonc

Scipt files should be placed in the OpenWrt router filesystem according to the repo directory structure, ensure that the following files have been granted executable permission:
* /etc/hotplug.d/iface/30-wanmonitor
* /etc/init.d/wanmonitor

```shell
chmod +x /etc/hotplug.d/iface/30-wanmonitor
chmod +x /etc/init.d/wanmonitor
```

Once the configuration file has been updated to match your local setup the service can be enabled and started by running the following commands from shell:
```shell
service wanmonitor enable
service wanmonitor start
```

# wanmonitor configuration options
The service configuration is controlled through the config file:
/etc/config/wanmonitor

A valid WAN interface name should be specified for each wanmonitor config section.

Option | Type | Description | Examples | Default
------------ | ------------- | ------------- | ------------- | -------------
enabled | boolean | Enable monitoring for an interface | 0 or 1 | 0 (disabled)
reconnect | boolean | Enable automatic reconnect of an interface that loses connectivity (optional) | 0 or 1 | 0 (disabled)
autorate | boolean | Enable automatic rate adjustment for interface SQM cake qdiscs (optional) | 0 or 1 | 0 (disabled)
egressTarget | decimal | Target rate percentage for the interface egress in decimal form 0 to 1 (optional) | 0.8| 0.8 (80%)
ingressTarget | decimal | Target rate percentage for the interface ingress in decimal form 0 to 1 (optional) | 0.7 | 0.8 (80%)
ingressDevice | string | Used to specify an alternative ingress device such as a veth or lan interface (optional) | br-lan |
interval | decimal | Specifies the ping test interval in seconds (optional) | 0.5 | 0.5 seconds
hosts | list | Specify the remote hosts to ping tests (optional) || connectivitycheck.gstatic.com<br>www.msftconnecttest.com<br>ipv6.msftconnecttest.com<br>captive.apple.com
iptype | string | Limit ping tests to a specific IP version (optional) | ipv4, ipv6 |
verbose | boolean | Enable detailed output in the wanmonitor var status file (optional) | 0 or 1 | 0 (disabled)
