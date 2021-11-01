Copyright 2021 Jack Everley

# wanmonitor
A set of scripts providing WAN interface monitoring and SQM autoscaling for OpenWrt routers.

The main lua executable currently supports the folling features:

* Autorate of both ingress and egress (comparing metrics in each direction to determine the most likely cause of latency)
* Support for monitoring multiple wan interfaces in parallel
* Polling of multiple remote hosts during each statistics interval (using the oping binary)
* Statistic intervals less than 1 second
* Automatic reconnect of non-responsive WAN interfaces
* Automatic detection of SQM configuration changes
* All configuration is managed using the standard OpenWrt configuration format
* The service is compatible with using secondary ingress qdisc devices such as a veth/lan interface for layer-cake ingress shaping
* Readout of current ping, ingress and egress metrics to a JSON file in /var/wanmonitor.{interface}.json (can be used for creating dashboards)

# Setup
The following OpenWrt packages must be installed:
* oping
* liboping
* luaposix
* luci-lib-jsonc (part of the default install)

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
It is recommended that the ingress and egress target parateters are set in the 0.7-0.8 range (exact values will depend on your setup).

**The values do not determine the link's maximum bandwith, they are used in the metric comparisons to account for rate jitter.**

Note that these should be set to configured to match the troughs of a saturated line rate as shown below:

![image](https://user-images.githubusercontent.com/46714706/139727270-ac732c63-e33d-4d1b-abb5-711700062220.png)

Good starting values are of 0.7 for ingress and 0.8 for egress.

Option | Type | Description | Examples | Default
------------ | ------------- | ------------- | ------------- | -------------
enabled | boolean | Enable monitoring for an interface | 0 or 1 | 0 (disabled)
reconnect | boolean | Enable automatic reconnect of an interface that loses connectivity (optional) | 0 or 1 | 0 (disabled)
autorate | boolean | Enable automatic rate adjustment for interface SQM cake qdiscs (optional) | 0 or 1 | 0 (disabled)
egressTarget | decimal | Target rate percentage for the interface egress in decimal form 0 to 1 (optional) | 0.8| 0.8 (80%)
ingressTarget | decimal | Target rate percentage for the interface ingress in decimal form 0 to 1 (optional) | 0.7 | 0.7 (70%)
ingressDevice | string | Used to specify an alternative ingress device such as a veth or lan interface (optional) | br-lan |
interval | decimal | Specifies the ping test interval in seconds (optional) | 0.5 | 0.5 seconds
hosts | list | Specify the remote hosts to ping tests (optional) || connectivitycheck.gstatic.com<br>www.msftconnecttest.com<br>ipv6.msftconnecttest.com<br>captive.apple.com
iptype | string | Limit ping tests to a specific IP version (optional) | ipv4, ipv6 |
verbose | boolean | Enable detailed output in the wanmonitor var status file (optional) | 0 or 1 | 0 (disabled)

# wan interface statistics
The service updates a JSON var file under the path /var/wanmonitor.{interface}.json which includes current rate and ping metrics.
Example below:

```json
{
  "ping": 48.56,
  "device": "wwan0",
  "egress": {
    "change": 0,
    "maximum": 115.47821693868875,
    "device": "wwan0",
    "peak": 2058.9358297866193,
    "decreaseChance": 0,
    "bandwidth": 1971.064,
    "target": 1647.1486638292954,
    "stable": 123.19589644945944,
    "rate": 101.49652326663251
  },
  "ingress": {
    "change": 3.407471957072835,
    "maximum": 12762.418651098951,
    "device": "br-lan",
    "peak": 34640.78843586186,
    "decreaseChance": 0,
    "bandwidth": 27601.920000000002,
    "target": 24248.5519051033,
    "stable": 12299.174989053196,
    "rate": 12762.418651098951
  },
  "interface": "wwan"
}
```
