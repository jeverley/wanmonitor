--[[
Copyright 2021 Jack Everley
Lua script for monitoring an OpenWrt WAN interface and auto-adjusting SQM cake egress and ingress bandwidth
Command line arguments:
	required	-i	(--interface)		Specifies the wan interface to monitor
	optional	-c	(--console)		Run attached to an interactive shell
	optional	-v	(--verbose)		Print all ping intervals
	optional	-l	(--log)			Write intervals to log file path
]]

local jsonc = require("luci.jsonc")
local signal = require("posix.signal")
local syslog = require("posix.syslog")
local systime = require("posix.sys.time")
local unistd = require("posix.unistd")

local egress
local device
local ingress
local interface
local pid
local pidChild
local pidFile
local ping
local statusFile

local autorate
local console
local dscp
local hosts
local interval
local iptype
local logfile
local mssJitterFix
local reconnect
local rtt
local stableDecreaseResistance
local stableDecreaseStepTime
local stableIncreaseResistance
local stableIncreaseStepTime
local stableTime
local verbose

local hostCount
local intervalEpoch
local pingStatus
local previousEpoch
local previousRxBytes
local previousTxBytes
local responseCount
local retries
local retriesRemaining

if not table.unpack then
	table.unpack = unpack
end

local function log(priority, message)
	syslog.openlog("wanmonitor", syslog.LOG_PID, syslog.LOG_DAEMON)
	syslog.syslog(syslog[priority], message)
	syslog.closelog()
	if console then
		print(message)
	end
end

local function cleanup()
	if pidChild then
		signal.kill(pidChild, signal.SIGKILL)
	end
	os.remove(pidFile)
	os.remove(statusFile)
end

local function exit()
	cleanup()
	os.exit()
end

local function resetMssJitterFix()
	egress.mssJitterFix = nil
	ingress.mssJitterFix = nil
	if pidChild then
		signal.kill(pidChild, signal.SIGKILL)
		pingStatus = 3
	end
end

local function epoch()
	local now = systime.gettimeofday()
	return now.tv_sec + now.tv_usec * 0.000001
end

local function sum(values)
	local total = 0
	for i = 1, #values do
		total = total + values[i]
	end
	return total
end

local function updateSample(sample, observation, period)
	table.insert(sample, observation)
	while #sample > period do
		table.remove(sample, 1)
	end
end

local function mean(sample)
	return sum(sample) / #sample
end

local function median(values)
	local sorted = {}
	for i = 1, #values do
		table.insert(sorted, values[i])
	end
	table.sort(sorted)
	local middle = #sorted * 0.5
	if #sorted % 2 == 0 then
		return (sorted[middle] + sorted[middle + 1]) * 0.5
	end
	return sorted[middle + 0.5]
end

local function streamingMedian(persist, observation, minimumStep)
	if not persist.median or not persist.step then
		persist.median = observation
		persist.step = math.max(math.abs(observation / 2), 1)
	end
	if minimumStep and persist.step < minimumStep then
		persist.step = minimumStep
	end
	if persist.median > observation then
		persist.median = persist.median - persist.step
	elseif persist.median < observation then
		persist.median = persist.median + persist.step
	end
	if math.abs(observation - persist.median) < persist.step then
		persist.step = persist.step / 2
	end
	return persist.median
end

local function readFile(file)
	local fd = io.open(file, "rb")
	local content = fd:read("*all")
	fd:close()
	return content
end

local function writeFile(file, content, mode)
	if not mode then
		mode = "wb"
	end
	local fd = io.open(file, mode)
	fd:write(content)
	fd:close()
end

local function execute(command)
	local fd = io.popen(command)
	local stdout = fd:read("*all")
	fd:close()
	return string.gsub(stdout, "^(.-)\n?$", "%1")
end

local function toboolean(input)
	if type(input) == "boolean" then
		return input
	elseif input == "true" or tonumber(input) == 1 then
		return true
	elseif input == "false" or tonumber(input) == 0 then
		return false
	end
end

local function readArg(short, long)
	local present
	local values = {}
	for i = 1, #arg do
		if present then
			if string.find(arg[i], "^%-") then
				break
			end
			table.insert(values, arg[i])
		elseif
			short and string.find(arg[i], "^%-" .. short .. "$")
			or long and string.find(arg[i], "^%-%-" .. long .. "$")
		then
			present = true
		end
	end

	if values[2] then
		return values
	elseif values[1] then
		return values[1]
	end
	return present
end

local function uciGet(config, section, option, sectionType)
	local response = jsonc.parse(execute("ubus call uci get '" .. jsonc.stringify({
		config = config,
		section = section,
		option = option,
		type = sectionType,
	}) .. "'"))

	if not response then
		return
	end
	if response.values then
		return response.values
	end
	return response.value
end

local function interfaceStatus(interface)
	return jsonc.parse(execute("ubus call network.interface." .. interface .. " status 2>/dev/null"))
end

local function firewallZoneConfig(zone)
	local zones = uciGet("firewall", nil, nil, "zone")
	if not zones then
		return
	end
	for k, v in pairs(zones) do
		if v.name == zone then
			return v
		end
	end
end

local function interfaceReconnect(interface)
	if not reconnect then
		return
	end

	log("LOG_WARNING", "Requesting ifup for " .. interface)
	cleanup()
	os.execute("ifup " .. interface)
	os.exit()
end

local function iptablesRuleCleanup(table, chain, rule)
	local escapedRule = string.gsub(rule, "([().%+-*?[^$])", "%%%1")
	for line in string.gmatch(execute("iptables -t " .. table .. " -S " .. chain), "([^\n]*)\n?") do
		if string.find(line, escapedRule) then
			os.execute("iptables -t " .. table .. " -D " .. chain .. " " .. rule)
		end
	end
	for line in string.gmatch(execute("ip6tables -t " .. table .. " -S " .. chain), "([^\n]*)\n?") do
		if string.find(line, escapedRule) then
			os.execute("ip6tables -t " .. table .. " -D " .. chain .. " " .. rule)
		end
	end
end

local function mssClamp(qdisc)
	if not mssJitterFix or not qdisc.bandwidth then
		return
	end

	local direction
	local directionArg
	if qdisc.device == device then
		direction = "egress"
		directionArg = "-i"
	else
		direction = "ingress"
		directionArg = "-o"
	end
	local pmtuClampArgs =
		'-p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "!fw3: Zone wan MTU fixing" -j TCPMSS --clamp-mss-to-pmtu'
	local jitterClampArgs =
		'-p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "Clamp MSS to reduce jitter" -j TCPMSS --set-mss 540'

	if qdisc.bandwidth < 3000 and qdisc.mssJitterFix ~= true then
		iptablesRuleCleanup("mangle", "FORWARD", directionArg .. " " .. device .. " " .. pmtuClampArgs)
		iptablesRuleCleanup("mangle", "FORWARD", directionArg .. " " .. device .. " " .. jitterClampArgs)
		os.execute("iptables -t mangle -A FORWARD " .. directionArg .. " " .. device .. " " .. jitterClampArgs)
		os.execute("ip6tables -t mangle -A FORWARD " .. directionArg .. " " .. device .. " " .. jitterClampArgs)
		qdisc.mssJitterFix = true
	elseif qdisc.bandwidth >= 3000 and qdisc.mssJitterFix ~= false then
		iptablesRuleCleanup("mangle", "FORWARD", directionArg .. " " .. device .. " " .. pmtuClampArgs)
		iptablesRuleCleanup("mangle", "FORWARD", directionArg .. " " .. device .. " " .. jitterClampArgs)
		local wan = firewallZoneConfig("wan")
		if wan and toboolean(wan.mtu_fix) == true then
			os.execute("iptables -t mangle -A FORWARD " .. directionArg .. " " .. device .. " " .. pmtuClampArgs)
			os.execute("ip6tables -t mangle -A FORWARD " .. directionArg .. " " .. device .. " " .. pmtuClampArgs)
		end
		qdisc.mssJitterFix = false
	end
end

local function writeStatus()
	writeFile(
		statusFile,
		jsonc.stringify({
			interface = interface,
			device = device,
			ping = ping,
			egress = egress,
			ingress = ingress,
		})
	)
end

local function adjustmentLog()
	if not logfile and not console then
		return
	end

	if
		not (ingress.change and ingress.change ~= 0)
		and not (egress.change and egress.change ~= 0)
		and not (ping.current and ping.limit and ping.current > ping.limit)
		and not verbose
	then
		return
	end

	local ingressUtilisation = ingress.utilisation
	local ingressBandwidth = 0
	local ingressDecreaseChance = 0
	if ingress.bandwidth then
		ingressBandwidth = ingress.bandwidth
	end
	if ingress.decreaseChance then
		ingressDecreaseChance = ingress.decreaseChance
	end

	local egressUtilisation = egress.utilisation
	local egressBandwidth = 0
	local egressDecreaseChance = 0
	if egress.bandwidth then
		egressBandwidth = egress.bandwidth
	end
	if egress.decreaseChance then
		egressDecreaseChance = egress.decreaseChance
	end

	local logLine = string.format("%.4f", intervalEpoch)
		.. ";	"
		.. string.format("%.3f", ingressUtilisation)
		.. ";	"
		.. string.format("%.3f", egressUtilisation)
		.. ";	"
		.. string.format("%.2f", ping.baseline)
		.. ";	"
		.. string.format("%.2f", ping.current)
		.. ";	"
		.. string.format("%.2f", ping.delta)
		.. ";	"
		.. string.format("%.2f", ingressBandwidth)
		.. ";	"
		.. string.format("%.2f", egressBandwidth)
		.. ";	"
		.. string.format("%.2f", ingress.rate)
		.. ";	"
		.. string.format("%.2f", egress.rate)
		.. ";	"
		.. string.format("%.2f", ingress.assured)
		.. ";	"
		.. string.format("%.2f", egress.assured)
		.. ";	"
		.. string.format("%.2f", ingress.stable)
		.. ";	"
		.. string.format(
			"%.2f",
			egress.stable
		)
		.. ";	"
		.. string.format(
			"%.2f",
			ingressDecreaseChance
		)
		.. ";	"
		.. string.format(
			"%.2f",
			egressDecreaseChance
		)
		.. ";"

	if console then
		print(logLine)
	end
	if logfile then
		os.execute("mkdir -p $(dirname '" .. logfile .. "')")
		writeFile(logfile, logLine .. "\n", "a")
	end
end

local function getQdisc(qdisc)
	if not qdisc.device then
		return
	end

	local tc = jsonc.parse(execute("tc -j qdisc show dev " .. qdisc.device))

	if tc[1].kind ~= "cake" or not tonumber(tc[1].options.bandwidth) or not tc[1].handle then
		qdisc.bandwidth = nil
		qdisc.handle = nil
		qdisc.kind = nil
		return
	end

	qdisc.bandwidth = tc[1].options.bandwidth * 0.008
	qdisc.handle = tc[1].handle
	qdisc.kind = tc[1].kind
end

local function updateQdisc(qdisc)
	if not qdisc.change or qdisc.change == 0 then
		return
	end

	local bps = math.floor((qdisc.bandwidth + qdisc.change) * 125)
	if
		os.execute(
			"tc qdisc change"
				.. " handle "
				.. qdisc.handle
				.. " dev "
				.. qdisc.device
				.. " "
				.. qdisc.kind
				.. " bandwidth "
				.. bps
				.. "bps"
		) == 0
	then
		qdisc.bandwidth = bps * 0.008
	end
end

local function updatePingStatistics()
	if not ping.baseline then
		ping.baseline = 50
		ping.clear = 0
		ping.median = rtt
		ping.step = 2
	end

	ping.delta = ping.current - ping.baseline
	ping.baseline = streamingMedian(ping, ping.current, 0.1)
	ping.limit = ping.baseline + 5
	ping.ceiling = ping.baseline + 70

	if ping.current > ping.limit then
		ping.clear = 0
		return
	end

	ping.clear = ping.clear + interval
end

local function updateRateStatistics(qdisc)
	if not qdisc.maximum or qdisc.rate > qdisc.maximum then
		qdisc.maximum = qdisc.rate
	end

	if qdisc.bandwidth then
		qdisc.utilisation = qdisc.rate / qdisc.bandwidth
	else
		qdisc.utilisation = 0
	end
end

local function calculateAssuredRate(qdisc)
	if not qdisc.assuredProportion then
		qdisc.assuredProportion = 1
		qdisc.assuredSample = {}
	end

	if ping.current > ping.limit then
		if qdisc.assuredProportion >= 0 + interval * 0.1 then
			qdisc.assuredProportion = qdisc.assuredProportion - interval * 0.1
		end
		qdisc.latent = true
	else
		qdisc.assuredProportion = 1
		qdisc.latent = nil
	end

	if qdisc.latent and qdisc.assuredSample[1] and math.max(table.unpack(qdisc.assuredSample)) > qdisc.bandwidth then
		for i = #qdisc.assuredSample, 1, -1 do
			if qdisc.assuredSample[i] > qdisc.bandwidth then
				table.remove(qdisc.assuredSample, i)
			end
		end
		qdisc.assuredProportion = 1 - interval * 0.1
		table.insert(qdisc.assuredSample, qdisc.bandwidth)
	end

	updateSample(qdisc.assuredSample, qdisc.rate, 5 / interval)
	local assuredMin = math.min(table.unpack(qdisc.assuredSample))
	local assuredMax = math.max(table.unpack(qdisc.assuredSample))
	qdisc.assured = assuredMin * (1 - qdisc.assuredProportion) + assuredMax * qdisc.assuredProportion
end

local function calculateStableRate(qdisc)
	if not qdisc.stable then
		qdisc.stable = math.max(qdisc.rate * 0.8, qdisc.bandwidth * 0.01)
	end

	if ping.current < ping.baseline and qdisc.rate > qdisc.stable then
		qdisc.stable = qdisc.rate
		return
	end

	if qdisc.rate > qdisc.stable then
		qdisc.stable = stableIncreaseResistance * qdisc.stable + (1 - stableIncreaseResistance) * qdisc.rate
	elseif qdisc.rate < qdisc.stable then
		qdisc.stable = stableDecreaseResistance * qdisc.stable + (1 - stableDecreaseResistance) * qdisc.rate
	end
end

local function calculateDecreaseChance(qdisc, compared)
	if not qdisc.stable then
		qdisc.stable = math.max(qdisc.rate * 0.8, qdisc.bandwidth * 0.01)
	end

	if not qdisc.bandwidth or ping.current < ping.limit or qdisc.rate <= qdisc.stable then
		qdisc.stableComparision = nil
		qdisc.decreaseChance = nil
		qdisc.decreaseChanceReducer = nil
		return
	end

	qdisc.stableComparision = (qdisc.rate - qdisc.stable) / qdisc.stable
	qdisc.decreaseChanceReducer = 1

	if compared.utilisation and compared.utilisation > 1.111 then
		qdisc.decreaseChanceReducer = qdisc.decreaseChanceReducer * 0.7 / compared.utilisation
	end

	if compared.utilisation < 0.9 and qdisc.utilisation > 0.9 then
		qdisc.decreaseChanceReducer = qdisc.decreaseChanceReducer * 1.2
	end

	if
		compared.assured
		and compared.rate < compared.stable
		and compared.rate / compared.assured > 0.6
		and compared.rate / compared.assured < 0.8
	then
		qdisc.decreaseChanceReducer = qdisc.decreaseChanceReducer * 0.1
	end

	qdisc.decreaseChance = qdisc.stableComparision * qdisc.decreaseChanceReducer
end

local function adjustDecreaseChance(qdisc, compared)
	if not qdisc.decreaseChance then
		return
	end

	local amplify = 7
	if not compared.decreaseChance then
		if qdisc.decreaseChance > 1 then
			qdisc.decreaseChance = 1
		end
	elseif qdisc.decreaseChance < compared.decreaseChance then
		if compared.decreaseChance > 1 then
			qdisc.decreaseChance = qdisc.decreaseChance / compared.decreaseChance
			qdisc.decreaseChance = qdisc.decreaseChance * qdisc.decreaseChance ^ amplify
			compared.decreaseChance = 1
		else
			qdisc.decreaseChance = qdisc.decreaseChance * (qdisc.decreaseChance / compared.decreaseChance) ^ amplify
		end
	elseif qdisc.decreaseChance > 1 then
		compared.decreaseChance = compared.decreaseChance / qdisc.decreaseChance
		qdisc.decreaseChance = 1
	end
	if qdisc.decreaseChance < 0.001 then
		qdisc.decreaseChance = nil
	end
end

local function calculateDecrease(qdisc)
	if ping.current < ping.ceiling then
		qdisc.decreaseChance = qdisc.decreaseChance * (ping.current / ping.ceiling) ^ 2
	else
		qdisc.decreaseChance = qdisc.decreaseChance ^ 0.6
	end
	qdisc.change = (qdisc.bandwidth - math.max(qdisc.maximum * 0.01, qdisc.assured)) * qdisc.decreaseChance * -1

	if qdisc.change > -0.008 then
		qdisc.change = 0
	end
end

local function calculateIncrease(qdisc)
	local targetMultiplier = math.max(qdisc.bandwidth * 0.9, qdisc.maximum) / qdisc.bandwidth
	if targetMultiplier < 1 then
		targetMultiplier = targetMultiplier ^ 15
	end
	local idleMultiplier = 1 - qdisc.utilisation * 0.7

	qdisc.change = qdisc.bandwidth * 0.05 * targetMultiplier * idleMultiplier

	if qdisc.change < 0.008 then
		qdisc.change = 0
	end
end

local function calculateChange(qdisc)
	if not qdisc.bandwidth then
		qdisc.change = nil
		return
	end

	if qdisc.decreaseChance then
		calculateDecrease(qdisc)
		return
	end

	if
		ping.clear > stableTime
		and math.random(1, 100) <= 75 * interval
		and (qdisc.assured > qdisc.bandwidth * 0.999 or qdisc.utilisation < 0.6)
	then
		calculateIncrease(qdisc)
		return
	end

	qdisc.change = 0
end

local function adjustSqm()
	if not autorate or not egress.rate or not ingress.rate then
		return
	end

	getQdisc(egress)
	getQdisc(ingress)

	updatePingStatistics()
	updateRateStatistics(egress)
	updateRateStatistics(ingress)

	calculateAssuredRate(egress)
	calculateAssuredRate(ingress)

	calculateStableRate(egress)
	calculateStableRate(ingress)

	calculateDecreaseChance(egress, ingress)
	calculateDecreaseChance(ingress, egress)
	adjustDecreaseChance(egress, ingress)
	adjustDecreaseChance(ingress, egress)

	calculateChange(egress)
	calculateChange(ingress)

	updateQdisc(egress)
	updateQdisc(ingress)

	mssClamp(egress)
	mssClamp(ingress)

	adjustmentLog()
end

local function statisticsInterval()
	local txBytes = tonumber(readFile("/sys/class/net/" .. device .. "/statistics/tx_bytes"))
	local rxBytes = tonumber(readFile("/sys/class/net/" .. device .. "/statistics/rx_bytes"))
	intervalEpoch = epoch()

	if not txBytes or not rxBytes then
		log("LOG_ERR", "Cannot read tx/rx rates for " .. interface .. " (" .. device .. ")")
		exit()
	end

	if previousTxBytes and previousRxBytes and previousEpoch then
		local timeDelta = intervalEpoch - previousEpoch
		egress.rate = (txBytes - previousTxBytes) * 0.008 / timeDelta
		ingress.rate = (rxBytes - previousRxBytes) * 0.008 / timeDelta
	end

	previousTxBytes = txBytes
	previousRxBytes = rxBytes
	previousEpoch = intervalEpoch

	if #ping.times > 0 then
		ping.current = math.min(table.unpack(ping.times))
	else
		ping.current = interval * 1000
		if ingress.rate == 0 then
			interfaceReconnect(interface)
		end
	end

	adjustSqm()
	writeStatus()
end

local function processPingOutput(line)
	if not line then
		return
	end

	if string.find(line, " from .* icmp_seq=.*") then
		responseCount = responseCount + 1

		local time = tonumber(string.match(line, "time=(%d+%.?%d*)"))
		if time then
			table.insert(ping.times, time)
		end

		if responseCount < hostCount then
			return
		end

		if #ping.times > 0 then
			pingStatus = 0
		else
			pingStatus = 1
		end

		statisticsInterval()
		ping.times = {}
		responseCount = 0
		retriesRemaining = retries
	elseif string.find(line, "Adding host .* failed: ") then
		log("LOG_WARNING", line)
		hostCount = hostCount - 1
		pingStatus = 4
	elseif
		string.find(line, "^Hangup$")
		or string.find(line, "^Killed$")
		or string.find(line, "^Terminated$")
		or string.find(line, " packets transmitted, .* received, .* packet loss, time .*ms")
	then
		pingStatus = 3
	elseif string.find(line, "ping_send failed: ") or string.find(line, "ping_sendto: Permission denied") then
		pingStatus = 2
	elseif string.find(line, "Invalid QoS argument:") then
		log("LOG_ERR", "Invalid dscp config value specified for " .. interface)
		exit()
	end
end

local function pingLoop()
	local deviceArg = "-D " .. device .. " "
	local dscpArg = "-Q " .. dscp .. " "
	local intervalArg = "-i " .. interval .. " "
	local timeoutArg = "-w " .. interval .. " "
	local iptypeArg = ""
	if iptype == "ipv4" then
		iptypeArg = "-4 "
	elseif iptype == "ipv6" then
		iptypeArg = "-6 "
	end

	hostCount = #hosts
	intervalEpoch = nil
	responseCount = 0
	ping = {}
	ping.times = {}
	pingStatus = nil
	previousRxBytes = nil
	previousTxBytes = nil
	previousEpoch = nil

	local fd = io.popen(
		"oping "
			.. deviceArg
			.. dscpArg
			.. intervalArg
			.. timeoutArg
			.. iptypeArg
			.. table.concat(hosts, " ")
			.. " 2>&1"
	)
	pidChild = execute("pgrep -n -x oping -P " .. pid)
	pidChild = tonumber(pidChild)

	repeat
		local line = fd:read("*line")
		processPingOutput(line)
	until not line
	fd:close()
	pidChild = nil
end

local function initialise()
	console = readArg("c", "console")
	interface = readArg("i", "interface")
	if type(interface) ~= "string" or interface == "" then
		log("LOG_ERR", "An interface must be specified for the -i (--interface) argument")
		os.exit()
	end

	statusFile = "/var/wanmonitor." .. interface .. ".json"
	pidFile = "/var/run/wanmonitor." .. interface .. ".pid"

	local config = uciGet("wanmonitor", interface)
	if not config or not toboolean(config.enabled) then
		os.exit()
	end

	local status = interfaceStatus(interface)
	if not status.up then
		os.exit()
	end
	device = status.l3_device
	if not device then
		log("LOG_ERR", "The device for interface " .. interface .. " is unavailable")
		os.exit()
	end

	hosts = {
		"connectivitycheck.gstatic.com",
		"www.msftconnecttest.com",
		"ipv6.msftconnecttest.com",
		"captive.apple.com",
	}
	egress = {}
	ingress = {}
	dscp = "CS6"
	interval = 0.5
	iptype = nil
	retries = 2
	reconnect = false
	autorate = false
	verbose = false
	logfile = nil

	if config.dscp then
		dscp = config.dscp
	end

	if config.interval then
		config.interval = tonumber(config.interval)
		if not config.interval or config.interval <= 0 then
			log("LOG_ERR", "Invalid interval config value specified for " .. interface)
			os.exit()
		else
			interval = config.interval
		end
	end

	if config.iptype and config.iptype ~= "ipv4" and config.iptype ~= "ipv6" and config.iptype ~= "ipv4v6" then
		log("LOG_ERR", "Invalid iptype config value specified for " .. interface)
		os.exit()
	end

	if config.iptype then
		iptype = config.iptype
	elseif status["ipv4-address"][1] and not status["ipv6-address"][1] then
		iptype = "ipv4"
	elseif status["ipv6-address"][1] and not status["ipv4-address"][1] then
		iptype = "ipv6"
	elseif not status["ipv4-address"][1] and not status["ipv6-address"][1] then
		local statusDynamicIpv4 = interfaceStatus(interface .. "_4")
		local statusDynamicIpv6 = interfaceStatus(interface .. "_6")
		if statusDynamicIpv4 and statusDynamicIpv4.dynamic and not statusDynamicIpv6 then
			iptype = "ipv4"
		elseif statusDynamicIpv6 and statusDynamicIpv6.dynamic and not statusDynamicIpv4 then
			iptype = "ipv6"
		end
	end

	if config.hosts then
		if type(config.hosts ~= "table") then
			log("LOG_ERR", "Invalid hosts list specified for " .. interface)
			os.exit()
		else
			hosts = config.hosts
		end
	end

	if config.reconnect then
		config.reconnect = toboolean(config.reconnect)
		if config.reconnect == nil then
			log("LOG_ERR", "Invalid reconnect config value specified for " .. interface)
			os.exit()
		else
			reconnect = config.reconnect
		end
	end

	if config.autorate then
		config.autorate = toboolean(config.autorate)
		if config.autorate == nil then
			log("LOG_ERR", "Invalid autorate config value specified for " .. interface)
			os.exit()
		else
			autorate = config.autorate
		end
	end

	if readArg("v", "verbose") then
		verbose = true
	elseif config.verbose then
		config.verbose = toboolean(config.verbose)
		if config.verbose == nil then
			log("LOG_ERR", "Invalid verbose config value specified for " .. interface)
			os.exit()
		else
			verbose = config.verbose
		end
	end

	local logfileArg = readArg("l", "log")
	if logfileArg then
		if type(logfileArg) == "string" and string.find(logfileArg, "^/[^%$]*$") then
			logfile = logfileArg
		else
			log("LOG_ERR", "Invalid log arguement path")
			os.exit()
		end
	elseif config.logfile then
		if not string.find(config.logfile, "^/[^%$]*$") then
			config.logfile = nil
		end
		if config.logfile == nil then
			log("LOG_ERR", "Invalid logfile config value specified for " .. interface)
			os.exit()
		else
			logfile = config.logfile
		end
	end

	if not autorate then
		return
	end

	mssJitterFix = false
	stableDecreaseStepTime = 10
	stableIncreaseStepTime = 90
	rtt = 50
	stableTime = 0.5

	egress.device = device
	if not config.ingressDevice or device == config.ingressDevice then
		ingress.device = "ifb4" .. string.sub(device, 1, 11)
	else
		ingress.device = config.ingressDevice
	end

	if config.mssJitterFix then
		config.mssJitterFix = toboolean(config.mssJitterFix)
		if config.mssJitterFix == nil then
			log("LOG_ERR", "Invalid mssJitterFix config value specified for " .. interface)
			os.exit()
		else
			mssJitterFix = config.mssJitterFix
		end
	end

	if config.assuredDecreaseStepTime then
		config.assuredDecreaseStepTime = tonumber(config.assuredDecreaseStepTime)
		if not config.assuredDecreaseStepTime or config.assuredDecreaseStepTime <= 0 then
			log("LOG_ERR", "Invalid assuredDecreaseStepTime config value specified for " .. interface)
			os.exit()
		else
			assuredDecreaseStepTime = config.assuredDecreaseStepTime
		end
	end

	if config.stableIncreaseStepTime then
		config.stableIncreaseStepTime = tonumber(config.stableIncreaseStepTime)
		if not config.stableIncreaseStepTime or config.stableIncreaseStepTime <= 0 then
			log("LOG_ERR", "Invalid stableIncreaseStepTime config value specified for " .. interface)
			os.exit()
		else
			stableIncreaseStepTime = config.stableIncreaseStepTime
		end
	end

	if config.rtt then
		config.rtt = tonumber(config.rtt)
		if not config.rtt or config.rtt <= 0 then
			log("LOG_ERR", "Invalid rtt config value specified for " .. interface)
			os.exit()
		else
			rtt = config.rtt
		end
	end

	if config.stableTime then
		config.stableTime = tonumber(config.stableTime)
		if not config.stableTime or config.stableTime <= 0 then
			log("LOG_ERR", "Invalid stableTime config value specified for " .. interface)
			os.exit()
		else
			stableTime = config.stableTime
		end
	end

	stableDecreaseResistance = math.exp(math.log(0.5) / (stableDecreaseStepTime / interval))
	stableIncreaseResistance = math.exp(math.log(0.5) / (stableIncreaseStepTime / interval))
end

local function daemonise()
	if unistd.fork() ~= 0 then
		os.exit()
	end
	if unistd.fork() ~= 0 then
		os.exit()
	end
end

local function main()
	initialise()
	signal.signal(signal.SIGHUP, exit)
	signal.signal(signal.SIGINT, exit)
	signal.signal(signal.SIGTERM, exit)
	signal.signal(signal.SIGUSR1, resetMssJitterFix)

	if not console then
		daemonise()
	end
	pid = unistd.getpid()
	writeFile(pidFile, pid)

	log("LOG_NOTICE", "Started for " .. interface .. " (" .. device .. ")")

	retriesRemaining = retries
	while retriesRemaining > 0 do
		pingLoop()
		if pingStatus == 4 then
			interfaceReconnect(interface)
		end
		if pingStatus ~= 0 and pingStatus ~= 1 and pingStatus ~= 2 and pingStatus ~= 3 then
			break
		end
		if pingStatus == 2 then
			retriesRemaining = retriesRemaining - 1
			unistd.sleep(1)
		end
	end
	log("LOG_ERR", "Unable to ping remote hosts on " .. interface .. " (" .. device .. ")")

	exit()
end

main()
