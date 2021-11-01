# wanmonitor
A set of scripts providing WAN interface monitoring and SQM autoscaling for OpenWrt routers.

# OpenWrt package dependencies
* oping
* liboping
* luaposix
* luci-lib-jsonc

# wanmonitor configuration options
A valid WAN interface name should be specified for each wanmonitor config section.

Option | Type | Description | Example | Default
------------ | ------------- | ------------- | ------------- | -------------
enabled | boolean | Enable monitoring for an interface | 0 or 1 | 0 (disabled)
reconnect | boolean | Enable automatic reconnect of an interface that loses connectivity | 0 or 1 | 0 (disabled)
autorate | boolean | Enable automatic rate adjustment for interface SQM cake qdiscs | 0 or 1 | 0 (disabled)
verbose | boolean | Enable detailed output in the wanmonitor var status file | 0 or 1 | 0 (disabled)
egressTarget | decimal | Target rate percentage for the interface egress in decimal form 0 to 1 | 0 or 1 | 0.8 (80%)
ingressTarget | decimal | Target rate percentage for the interface ingress in decimal form 0 to 1 | 0 or 1 | 0.8 (80%)
