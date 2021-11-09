Copyright 2021 Jack Everley

# wanmonitor
A lua service providing WAN interface monitoring and adaptive bandwidth for SQM on OpenWrt routers.

The main lua executable currently supports the folling features:

* Adaptive bandwidth for both ingress and egress
* Support for monitoring multiple wan interfaces
* Polling of multiple remote hosts during each statistics interval (using the oping binary)
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

The following shell commands can be used to install the service:

```shell
opkg update
opkg install oping liboping luaposix
wget https://raw.githubusercontent.com/jeverley/wanmonitor/main/usr/sbin/wanmonitor.lua -O /usr/sbin/wanmonitor.lua
wget https://raw.githubusercontent.com/jeverley/wanmonitor/main/etc/config/wanmonitor -O /etc/config/wanmonitor
wget https://raw.githubusercontent.com/jeverley/wanmonitor/main/etc/hotplug.d/iface/30-wanmonitor -O /etc/hotplug.d/iface/30-wanmonitor
wget https://raw.githubusercontent.com/jeverley/wanmonitor/main/etc/init.d/wanmonitor -O /etc/init.d/wanmonitor
chmod +x /etc/hotplug.d/iface/30-wanmonitor
chmod +x /etc/init.d/wanmonitor
```



Once the configuration file has been updated to match your local setup the service can be enabled and started by running the following commands from shell:
```shell
service wanmonitor enable
service wanmonitor start
```

The service can alternatively be run attached to a user shell (ensure the device is stopped first), to do so execute a command using the '-c' argument, additionally passing '-v' will make the service print all intervals.

```shell
lua /usr/sbin/wanmonitor.lua -i wwan -c -v
```
An additional argument -l can be used to specify a log file path.
```shell
lua /usr/sbin/wanmonitor.lua -i wwan -c -v -l /tmp/wanmonitor.wwan.log
```

**The bandwidth rates configured for your download/upload under SQM setup are used by the service as starting points for adaptive bandwidth control.**

# wanmonitor configuration options
The service configuration is controlled through the config file:
/etc/config/wanmonitor

A valid WAN interface name should be specified for each wanmonitor config section.

It is recommended that the ingress and egress target parateters are set in the 0.7-0.8 range for a LTE link, please start with the defaults (exact values will depend on your setup).

**The values do not determine the link's maximum bandwith, they are used in the metric comparisons to account for rate jitter.**

Note that these should be configured to match the troughs of a saturated line rate as shown below:

![image](https://user-images.githubusercontent.com/46714706/139727270-ac732c63-e33d-4d1b-abb5-711700062220.png)

Option | Type | Description | Examples | Default
------------ | ------------- | ------------- | ------------- | -------------
enabled | boolean | Enable monitoring for an interface | 0 or 1 | 0 (disabled)
reconnect | boolean | Enable automatic reconnect of an interface that loses connectivity (optional) | 0 or 1 | 0 (disabled)
autorate | boolean | Enable automatic rate adjustment for interface SQM cake qdiscs (optional) | 0 or 1 | 0 (disabled)
egressTarget | decimal | Target rate percentage for the interface egress in decimal form 0 to 1 (optional) | 0.8| 0.8 (80%)
ingressTarget | decimal | Target rate percentage for the interface ingress in decimal form 0 to 1 (optional) | 0.7 | 0.7 (70%)
ingressDevice | string | Used to specify an alternative ingress device such as a veth or lan interface (optional) | br-lan |
interval | decimal | Specifies the ping test interval in seconds (optional) | 0.5 | 0.5 seconds
rtt | decimal | Specifies the link's typical uncongested ping milliseconds (optional) | 50 | 50
hosts | list | Specify the remote hosts to ping tests (optional) || connectivitycheck.gstatic.com<br>www.msftconnecttest.com<br>ipv6.msftconnecttest.com<br>captive.apple.com
iptype | string | Limit ping tests to a specific IP version (optional) | ipv4, ipv6 |
verbose | boolean | Enable detailed output in the wanmonitor log file (optional) | 0 or 1 | 0 (disabled)
logFile | string | File path for log file (optional) | /tmp/wanmonitor.wwan.log |

# wan interface statistics
The service updates a JSON var file under the path /var/wanmonitor.{interface}.json which includes current rate and ping metrics.
Example below:

```json
{
    "ping": 34.359999999999999,
    "pingBaseline": 28.62471516775733,
    "device": "wwan0",
    "egress": {
        "bandwidth": 981.91200000000003,
        "maximum": 1385.8266554230368,
        "device": "wwan0",
        "change": 0,
        "rate": 407.34954748331836,
        "target": 1385.8266554230368
    },
    "ingress": {
        "bandwidth": 19777.312000000002,
        "maximum": 31009.577300174991,
        "device": "br-lan",
        "change": 0,
        "rate": 11464.306138738317,
        "target": 31009.577300174991
    },
    "interface": "wwan"
}
```
