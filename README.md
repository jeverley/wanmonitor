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
Log format headers:
Ingress utilisation | Egress utilisation | Ping baseline | Ping | Ping delta | Ingress bandwidth | Egress bandwidth | Ingress rate | Egress rate | Ingress assured | Egress assured
------------ | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------

**The bandwidth rates configured for your download/upload under SQM setup are used by the service as starting points for adaptive bandwidth control.**

# wanmonitor configuration options
The service configuration is controlled through the config file:
/etc/config/wanmonitor

A valid WAN interface name should be specified for each wanmonitor config section.

It is recommended that the ingress and egress assured parateters are set in the 0.8-0.9 range for an LTE link, please start with the defaults (exact values will depend on your setup).

**The values do not determine the link's maximum bandwith, they are used to compensate for rate jitter.**

Note that these should be configured to match the troughs of a saturated line rate as shown below:

![image](https://user-images.githubusercontent.com/46714706/139727270-ac732c63-e33d-4d1b-abb5-711700062220.png)

Option | Type | Description | Examples | Default
------------ | ------------- | ------------- | ------------- | -------------
enabled | boolean | Enable monitoring for an interface | 0 or 1 | 0 (disabled)
reconnect | boolean | Enable automatic reconnect of an interface that loses connectivity (optional) | 0 or 1 | 0 (disabled)
autorate | boolean | Enable automatic rate adjustment for interface SQM cake qdiscs (optional) | 0 or 1 | 0 (disabled)
ingressDevice | string | Used to specify an alternative ingress device such as a veth or lan interface (optional) | br-lan |
interval | decimal | Specifies the ping test interval in seconds (optional) | 0.5 | 0.5 seconds
rtt | decimal | Specifies the link's typical uncongested ping milliseconds (optional) | 50 | 50
hosts | list | Specify the remote hosts to ping tests (optional) || connectivitycheck.gstatic.com<br>www.msftconnecttest.com<br>ipv6.msftconnecttest.com<br>captive.apple.com
iptype | string | Limit ping tests to a specific IP version (optional) | ipv4, ipv6 |
verbose | boolean | Enable detailed output in the wanmonitor log file (optional) | 0 or 1 | 0 (disabled)
mssJitterFix | boolean | Clamp/unclamp TCP MSS to 540 to reduce jitter if bandwidth falls below/rises above 3000kbps (optional) | 0 or 1 | 0 (disabled)
logfile | string | File path for log file (optional) | /tmp/wanmonitor.wwan.log |

# wan interface statistics
The service updates a JSON var file under the path /var/wanmonitor.{interface}.json which includes current rate and ping metrics.
Example below:

```json
{
    "ping": {
        "clear": 0,
        "current": 48.719999999999999,
        "limit": 46.0400390625,
        "times": [
            48.719999999999999,
            63.289999999999999,
            55.409999999999997
        ],
        "baseline": 41.0400390625,
        "ceiling": 96.0400390625,
        "streamingMedian": {
            "median": 41.0400390625,
            "step": 0.006103515625
        }
    },
    "device": "wwan0",
    "egress": {
        "latent": false,
        "utilisation": 0.0045528814157078457,
        "bandwidth": 1199.5599999999999,
        "handle": "9c8a:",
        "assured": 307.52527285440124,
        "assuredTarget": 0.90000000000000002,
        "maximum": 1137.252768593685,
        "device": "wwan0",
        "rate": 5.4614544310265032,
        "assuredSample": [
            1136.9213454541516,
            842.58915135049858,
            477.91355857495455
        ],
        "change": 0,
        "kind": "cake",
        "stable": 307.52527285440124,
        "mssJitterFix": true
    },
    "ingress": {
        "latent": false,
        "utilisation": 0.00024180351732188763,
        "bandwidth": 22520.864000000001,
        "handle": "9c87:",
        "assured": 136.05987120168882,
        "assuredTarget": 0.90000000000000002,
        "maximum": 19312.318198628818,
        "device": "br-lan",
        "rate": 5.4456241283278759,
        "assuredSample": [
            2721.3730865928183,
            149.85666008578772
        ],
        "change": 0,
        "mssJitterFix": false,
        "stable": 136.05987120168882,
        "kind": "cake"
    },
    "interface": "wwan"
}
```
