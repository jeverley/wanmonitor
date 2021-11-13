--[[
Copyright 2021 Jack Everley
Lua script for monitoring a wan interface and auto-adjusting its qdiscs' bandwidth for SQM
Command line arguments:
	required	-i	(--interface)	Used to specify the wan interface to monitor
]]

local jsonc = require("luci.jsonc")
local signal = require("posix.signal")
local syslog = require("posix.syslog")
local systime = require("posix.sys.time")
local unistd = require("posix.unistd")

local egress
local ingress
local interface
local pid
local pidFile
local childPid
local ping
local pingStatus
local statusFile
local console
local verbose
local logFile

local device
local dscp
local hosts
local interval
local iptype
local pingIncreasePersistence
local pingDecreasePersistence
local shortPeakPersistence
local longPeakPersistence
local pingPersistence
local stablePersistence
local stableSeconds
local stablePeriod
local reconnect
local autorate
local rtt

local hostCount
local responseCount
local retries
local retriesRemaining
local previousRxBytes
local previousTxBytes
local previousEpoch
local intervalEpoch

local function log(priority, message)
	syslog.openlog("wanmonitor", syslog.LOG_PID, syslog.LOG_DAEMON)
	syslog.syslog(syslog[priority], message)
	syslog.closelog()
	if console then
		print(message)
	end
end

local function cleanup()
	if childPid then
		signal.kill(childPid, signal.SIGKILL)
	end
	if pidFile then
		os.remove(pidFile)
	end
	if statusFile then
		os.remove(statusFile)
	end
end

local function exit()
	cleanup()
	os.exit()
end

local function resetMssClamp()
	egress.mssClamp = nil
	ingress.mssClamp = nil
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

local function mean(sample)
	return sum(sample) / #sample
end

local function movingMean(sample, observation, period)
	table.insert(sample, observation)
	while #sample > period do
		table.remove(sample, 1)
	end
	return mean(sample)
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

local function wanFirewallConfig()
	local zones = uciGet("firewall", nil, nil, "zone")
	if not zones then
		return
	end
	for k, v in pairs(zones) do
		if v.name == "wan" then
			return v
		end
	end
end

local function interfaceStatus(interface)
	return jsonc.parse(execute("ubus call network.interface." .. interface .. " status 2>/dev/null"))
end

local function interfaceReconnect(interface)
	if not reconnect then
		return
	end

	local status = interfaceStatus(interface)
	if not status.up or status.pending then
		return
	end

	log("LOG_WARNING", "Requesting ifup for " .. interface)
	cleanup()
	os.execute("ifup " .. interface)
	os.exit()
end

local function updatePingStatistics()
	if not ping.baseline then
		ping.clear = 0
		ping.latent = 0
		ping.baseline = rtt
	end

	if ping.current > ping.baseline then
		ping.baseline = ping.baseline * pingIncreasePersistence + ping.current * (1 - pingIncreasePersistence)
	else
		ping.baseline = ping.baseline * pingDecreasePersistence + ping.current * (1 - pingDecreasePersistence)
	end

	ping.limit = ping.baseline * 1.9
	ping.target = ping.baseline * 1.4

	if ping.current > ping.limit then
		ping.clear = 0
		ping.latent = ping.latent + interval
		return
	end

	if ping.current > ping.target then
		ping.clear = 0
		ping.latent = 0
		return
	end

	ping.clear = ping.clear + interval
	ping.latent = 0
end

local function updateRateStatistics(qdisc)
	if not qdisc.kind then
		qdisc.assuredSample = nil
		qdisc.rateSample = nil
		qdisc.longPeak = nil
		qdisc.shortPeak = nil
		qdisc.mean = nil
		qdisc.maximum = nil
		qdisc.minimum = nil
		qdisc.stable = nil
		qdisc.target = nil
		qdisc.utilisation = nil
		return
	end

	local assured = qdisc.rate
	if ping.current > ping.target then
		assured = assured * qdisc.bandwidthTarget
	end

	if not qdisc.assuredSample then
		qdisc.assuredSample = {}
	end
	if not qdisc.rateSample then
		qdisc.rateSample = {}
	end

	local assuredMean = movingMean(qdisc.assuredSample, assured, stablePeriod)
	qdisc.mean = movingMean(qdisc.rateSample, qdisc.rate, stablePeriod)

	if not qdisc.stable or ping.current < ping.target then
		qdisc.stable = assuredMean
	else
		qdisc.stable = qdisc.stable * stablePersistence + assuredMean * (1 - stablePersistence)
	end

	if not qdisc.shortPeak then
		qdisc.shortPeak = qdisc.bandwidth
	elseif qdisc.rate > qdisc.shortPeak then
		qdisc.shortPeak = qdisc.rate
	else
		qdisc.shortPeak = qdisc.shortPeak * shortPeakPersistence + qdisc.rate * (1 - shortPeakPersistence)
	end

	if not qdisc.longPeak or qdisc.rate > qdisc.longPeak then
		qdisc.longPeak = qdisc.rate
	else
		qdisc.longPeak = qdisc.longPeak * longPeakPersistence + qdisc.rate * (1 - longPeakPersistence)
	end

	if not qdisc.maximum or assured > qdisc.maximum then
		qdisc.maximum = assured
	end

	qdisc.minimum = math.max(qdisc.stable, qdisc.maximum * 0.01)
	qdisc.target = math.max(qdisc.bandwidth * qdisc.bandwidthTarget, qdisc.maximum)
	qdisc.utilisation = qdisc.rate / qdisc.bandwidth
end

local function calculateDecreaseChance(qdisc)
	if not qdisc.kind or ping.current < ping.limit then
		qdisc.baselineComparision = nil
		qdisc.decreaseChance = nil
		qdisc.decreaseChanceReducer = nil
		return
	end

	local baseline = qdisc.stable * 0.4
		+ qdisc.mean * 0.1
		+ qdisc.shortPeak * qdisc.bandwidthTarget * 0.45
		+ qdisc.longPeak * qdisc.bandwidthTarget * 0.05
	qdisc.baselineComparision = (qdisc.rate - baseline) / baseline

	if ping.latent == interval or qdisc.cooldown == 0 then
		qdisc.decreaseChanceReducer = 0.5
	else
		qdisc.decreaseChanceReducer = 1
	end

	if qdisc.utilisation < 1 and qdisc.utilisation > 0.98 then
		qdisc.decreaseChanceReducer = qdisc.decreaseChanceReducer * 0.5
	end

	if qdisc.baselineComparision > 0 then
		qdisc.decreaseChance = qdisc.baselineComparision
	else
		qdisc.decreaseChance = nil
	end
end

local function adjustDecreaseChances()
	if not egress.decreaseChance and not ingress.decreaseChance then
		return
	end

	if egress.utilisation and ingress.utilisation then
		if egress.utilisation > 1 then
			ingress.decreaseChanceReducer = ingress.decreaseChanceReducer * 0.5 / egress.utilisation
		elseif egress.utilisation > 0.98 then
			ingress.decreaseChanceReducer = ingress.decreaseChanceReducer * 0.5
		elseif
			ingress.rate > ingress.mean * 0.9
			and egress.rate < egress.mean * 0.9
			and egress.rate > egress.mean * 0.8
		then
			ingress.decreaseChanceReducer = ingress.decreaseChanceReducer * 0.5
		end
		if ingress.utilisation > 1 then
			egress.decreaseChanceReducer = egress.decreaseChanceReducer * 0.5 / ingress.utilisation
		elseif ingress.utilisation > 0.98 then
			egress.decreaseChanceReducer = egress.decreaseChanceReducer * 0.5
		elseif
			egress.rate > egress.mean * 0.9
			and ingress.rate < ingress.mean * 0.9
			and ingress.rate > ingress.mean * 0.8
		then
			egress.decreaseChanceReducer = egress.decreaseChanceReducer * 0.5
		end
	end

	local pingReducer = 1 - ping.limit * 0.99 / ping.current
	if egress.decreaseChance then
		egress.decreaseChance = egress.baselineComparision * egress.decreaseChanceReducer * pingReducer
	end
	if ingress.decreaseChance then
		ingress.decreaseChance = ingress.baselineComparision * ingress.decreaseChanceReducer * pingReducer
	end

	local amplification = 10
	if egress.decreaseChance and not ingress.decreaseChance then
		if egress.decreaseChance > 1 then
			egress.decreaseChance = 1
		end
	elseif ingress.decreaseChance and not egress.decreaseChance then
		if ingress.decreaseChance > 1 then
			ingress.decreaseChance = 1
		end
	elseif egress.decreaseChance > ingress.decreaseChance then
		if egress.decreaseChance > 1 then
			ingress.decreaseChance = ingress.decreaseChance / egress.decreaseChance
			egress.decreaseChance = 1
		end
		ingress.decreaseChance = ingress.decreaseChance
			* (ingress.decreaseChance / egress.decreaseChance) ^ amplification
	elseif ingress.decreaseChance > egress.decreaseChance then
		if ingress.decreaseChance > 1 then
			egress.decreaseChance = egress.decreaseChance / ingress.decreaseChance
			ingress.decreaseChance = 1
		end
		egress.decreaseChance = egress.decreaseChance * (egress.decreaseChance / ingress.decreaseChance) ^ amplification
	elseif egress.decreaseChance > 1 then
		egress.decreaseChance = 1
		ingress.decreaseChance = 1
	end
end

local function updateCooldown(qdisc)
	if not qdisc.kind then
		qdisc.cooldown = nil
		return
	end

	if not qdisc.cooldown then
		qdisc.cooldown = 0
	end

	if qdisc.decreaseChance and qdisc.decreaseChance > 0.01 then
		qdisc.cooldown = qdisc.cooldown + interval
		return
	end

	if ping.current < ping.limit and qdisc.cooldown > 0 then
		qdisc.cooldown = qdisc.cooldown - interval
	end
end

local function calculateDecrease(qdisc)
	qdisc.change = (qdisc.bandwidth - qdisc.rate * 0.5) * qdisc.decreaseChance * -1
	if qdisc.bandwidth + qdisc.change < qdisc.minimum then
		qdisc.change = qdisc.minimum - qdisc.bandwidth
	end

	if qdisc.change > -0.008 then
		qdisc.change = 0
	end
end

local function calculateIncrease(qdisc)
	local targetMultiplier = qdisc.target / qdisc.bandwidth
	if targetMultiplier < 1 then
		targetMultiplier = targetMultiplier ^ 20
	end

	qdisc.change = qdisc.bandwidth * 0.1 * targetMultiplier

	if qdisc.change < 0.008 then
		qdisc.change = 0
	end
end

local function calculateChange(qdisc)
	if not qdisc.kind then
		qdisc.change = nil
		return
	end

	if qdisc.decreaseChance and qdisc.rate > qdisc.minimum then
		calculateDecrease(qdisc)
		return
	end

	if
		ping.current < ping.target
		and qdisc.cooldown == 0
		and ping.clear >= stableSeconds
		and (qdisc.stable > qdisc.bandwidth * 0.95 or math.random(1, 10) <= 5 * interval)
	then
		calculateIncrease(qdisc)
		return
	end

	qdisc.change = 0
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

local function writeStatus()
	if verbose then
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
		return
	end

	writeFile(
		statusFile,
		jsonc.stringify({
			interface = interface,
			device = device,
			pingBaseline = ping.baseline,
			ping = ping.current,
			egress = {
				device = egress.device,
				target = egress.target,
				bandwidth = egress.bandwidth,
				maximum = egress.maximum,
				rate = egress.rate,
				change = egress.change,
			},
			ingress = {
				device = ingress.device,
				target = ingress.target,
				bandwidth = ingress.bandwidth,
				maximum = ingress.maximum,
				rate = ingress.rate,
				change = ingress.change,
			},
		})
	)
end

local function adjustmentLog()
	if not logFile and not console then
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

	local ingressUtilisation = 0
	local ingressBandwidth = 0
	local ingressBaselineComparision = 0
	local ingressDecreaseChance = 0
	if ingress.bandwidth then
		ingressUtilisation = ingress.utilisation
		ingressBandwidth = ingress.bandwidth
	end
	if ingress.baselineComparision then
		ingressBaselineComparision = ingress.baselineComparision
	end
	if ingress.decreaseChance then
		ingressDecreaseChance = ingress.decreaseChance
	end

	local egressUtilisation = 0
	local egressBandwidth = 0
	local egressBaselineComparision = 0
	local egressDecreaseChance = 0
	if egress.bandwidth then
		egressUtilisation = egress.utilisation
		egressBandwidth = egress.bandwidth
	end
	if egress.baselineComparision then
		egressBaselineComparision = egress.baselineComparision
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
		.. string.format("%.2f", ping.current - ping.baseline)
		.. ";	"
		.. string.format("%.2f", ingressBandwidth)
		.. ";	"
		.. string.format("%.2f", egressBandwidth)
		.. ";	"
		.. string.format("%.2f", ingress.rate)
		.. ";	"
		.. string.format("%.2f", egress.rate)
		.. ";	"
		.. string.format("%.2f", ingressBaselineComparision)
		.. ";	"
		.. string.format("%.2f", ingressDecreaseChance)
		.. ";	"
		.. string.format(
			"%.2f",
			egressBaselineComparision
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
	if logFile then
		os.execute("mkdir -p $(dirname '" .. logFile .. "')")
		writeFile(logFile, logLine .. "\n", "a")
	end
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

	if qdisc.bandwidth < 3000 and qdisc.mssClamp ~= true then
		iptablesRuleCleanup("mangle", "FORWARD", directionArg .. " " .. device .. " " .. pmtuClampArgs)
		iptablesRuleCleanup("mangle", "FORWARD", directionArg .. " " .. device .. " " .. jitterClampArgs)
		os.execute("iptables -t mangle -A FORWARD " .. directionArg .. " " .. device .. " " .. jitterClampArgs)
		os.execute("ip6tables -t mangle -A FORWARD " .. directionArg .. " " .. device .. " " .. jitterClampArgs)
		log("LOG_INFO", interface .. " " .. direction .. " MSS clamped to 540")
		qdisc.mssClamp = true
	elseif qdisc.bandwidth >= 3000 and qdisc.mssClamp ~= false then
		iptablesRuleCleanup("mangle", "FORWARD", directionArg .. " " .. device .. " " .. pmtuClampArgs)
		iptablesRuleCleanup("mangle", "FORWARD", directionArg .. " " .. device .. " " .. jitterClampArgs)
		local wan = wanFirewallConfig()
		if wan and toboolean(wan.mtu_fix) == true then
			os.execute("iptables -t mangle -A FORWARD " .. directionArg .. " " .. device .. " " .. pmtuClampArgs)
			os.execute("ip6tables -t mangle -A FORWARD " .. directionArg .. " " .. device .. " " .. pmtuClampArgs)
			log("LOG_INFO", interface .. " " .. direction .. " MSS clamped to PMTU")
		end
		qdisc.mssClamp = false
	end
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

	calculateDecreaseChance(egress)
	calculateDecreaseChance(ingress)
	adjustDecreaseChances()

	updateCooldown(egress)
	updateCooldown(ingress)

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

	if not txBytes or not rxBytes or not intervalEpoch then
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
		ping.current = math.min(unpack(ping.times))
	else
		if ingress.rate == 0 then
			interfaceReconnect(interface)
		end
		ping.current = interval * 1000
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
	childPid = execute("pgrep -n -x oping -P " .. pid)

	repeat
		local line = fd:read("*line")
		processPingOutput(line)
	until not line
	fd:close()
	childPid = nil
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
	logFile = nil
	rtt = 50

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
		config.iptype = nil
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

	local logFileArg = readArg("l", "log")
	if logFileArg then
		if type(logFileArg) == "string" and string.find(logFileArg, "^/[^%$]*$") then
			logFile = logFileArg
		else
			log("LOG_ERR", "Invalid log arguement path")
			os.exit()
		end
	elseif config.logFile then
		if not string.find(config.logFile, "^/[^%$]*$") then
			config.logFile = nil
		end
		if config.logFile == nil then
			log("LOG_ERR", "Invalid logFile config value specified for " .. interface)
			os.exit()
		else
			logFile = config.logFile
		end
	end

	if logFile then
		os.remove(logFile)
	end

	if not autorate then
		return
	end

	pingIncreasePersistence = 0.985
	pingDecreasePersistence = 0.05
	shortPeakPersistence = 0.1
	longPeakPersistence = 0.98
	pingPersistence = 0.99
	stablePersistence = 0.9
	stableSeconds = 2
	egress.bandwidthTarget = 0.7
	ingress.bandwidthTarget = 0.7
	egress.device = device

	if not config.ingressDevice or device == config.ingressDevice then
		ingress.device = "ifb4" .. string.sub(device, 1, 11)
	else
		ingress.device = config.ingressDevice
	end

	if config.shortPeakPersistence then
		config.shortPeakPersistence = tonumber(config.shortPeakPersistence)
		if not config.shortPeakPersistence or config.shortPeakPersistence <= 0 or config.shortPeakPersistence > 1 then
			log("LOG_ERR", "Invalid shortPeakPersistence config value specified for " .. interface)
			os.exit()
		else
			shortPeakPersistence = config.shortPeakPersistence
		end
	end

	if config.longPeakPersistence then
		config.longPeakPersistence = tonumber(config.longPeakPersistence)
		if not config.longPeakPersistence or config.longPeakPersistence <= 0 or config.longPeakPersistence > 1 then
			log("LOG_ERR", "Invalid longPeakPersistence config value specified for " .. interface)
			os.exit()
		else
			longPeakPersistence = config.longPeakPersistence
		end
	end

	if config.pingPersistence then
		config.pingPersistence = tonumber(config.pingPersistence)
		if not config.pingPersistence or config.pingPersistence <= 0 or config.pingPersistence > 1 then
			log("LOG_ERR", "Invalid pingPersistence config value specified for " .. interface)
			os.exit()
		else
			pingPersistence = config.pingPersistence
		end
	end

	if config.stablePersistence then
		config.stablePersistence = tonumber(config.stablePersistence)
		if not config.stablePersistence or config.stablePersistence <= 0 or config.stablePersistence > 1 then
			log("LOG_ERR", "Invalid stablePersistence config value specified for " .. interface)
			os.exit()
		else
			stablePersistence = config.stablePersistence
		end
	end

	if config.stableSeconds then
		config.stableSeconds = tonumber(config.stableSeconds)
		if not config.stableSeconds or config.stableSeconds <= 0 then
			log("LOG_ERR", "Invalid stableSeconds config value specified for " .. interface)
			os.exit()
		else
			stableSeconds = config.stableSeconds
		end
	end

	if config.egressTarget then
		config.egressTarget = tonumber(config.egressTarget)
		if not config.egressTarget or config.egressTarget <= 0 or config.egressTarget > 1 then
			log("LOG_ERR", "Invalid egressTarget config value specified for " .. interface)
			os.exit()
		else
			egress.bandwidthTarget = config.egressTarget
		end
	end

	if config.ingressTarget then
		config.ingressTarget = tonumber(config.ingressTarget)
		if not config.ingressTarget or config.ingressTarget <= 0 or config.ingressTarget > 1 then
			log("LOG_ERR", "Invalid ingressTarget config value specified for " .. interface)
			os.exit()
		else
			ingress.bandwidthTarget = config.ingressTarget
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

	if config.mssJitterFix then
		config.mssJitterFix = toboolean(config.mssJitterFix)
		if config.mssJitterFix == nil then
			log("LOG_ERR", "Invalid mssJitterFix config value specified for " .. interface)
			os.exit()
		else
			mssJitterFix = config.mssJitterFix
		end
	end

	stablePeriod = stableSeconds / interval
	pingIncreasePersistence = pingIncreasePersistence ^ interval
	pingDecreasePersistence = pingDecreasePersistence ^ interval
	shortPeakPersistence = shortPeakPersistence ^ interval
	longPeakPersistence = longPeakPersistence ^ interval
	pingPersistence = pingPersistence ^ interval
	stablePersistence = stablePersistence ^ interval
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
	signal.signal(signal.SIGUSR1, resetMssClamp)

	if console then
		pid = unistd.getpid()
		pidFile = nil
	else
		daemonise()
		pid = unistd.getpid()
		writeFile(pidFile, pid)
	end

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
