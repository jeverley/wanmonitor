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

local hostsCount
local pingResponseCount
local pingResponseTimes
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
end

local function cleanup()
	if childPid then
		signal.kill(childPid, signal.SIGKILL)
	end
	os.remove(statusFile)
	os.remove(pidFile)
end

local function exit()
	cleanup()
	os.exit()
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

local function uciGet(config, section, option)
	local response = jsonc.parse(execute("ubus call uci get '" .. jsonc.stringify({
		config = config,
		section = section,
		option = option,
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

	ping.limit = ping.baseline * 2
	ping.target = ping.baseline * 1.3

	if ping.current > ping.limit then
		ping.clear = 0
		ping.latent = ping.latent + interval
		return
	end

	if ping.current > ping.target then
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

	if not qdisc.rateSample then
		qdisc.rateSample = {}
	end
	qdisc.mean = movingMean(qdisc.rateSample, qdisc.rate, stablePeriod)

	local assured
	if ping.current < ping.target then
		assured = qdisc.rate
	else
		assured = qdisc.rate * qdisc.bandwidthTarget
	end
	if not qdisc.assuredSample then
		qdisc.assuredSample = {}
	end
	local assuredMean = movingMean(qdisc.assuredSample, assured, stablePeriod)

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

	qdisc.minimum = math.max(qdisc.shortPeak * qdisc.bandwidthTarget, qdisc.stable, qdisc.maximum * 0.01)
	qdisc.target = math.max(qdisc.bandwidth * qdisc.bandwidthTarget, qdisc.maximum)
	qdisc.utilisation = qdisc.rate / qdisc.bandwidth
end

local function calculateDecreaseChance(qdisc)
	if not qdisc.kind then
		qdisc.decreaseChanceBaseline = nil
		qdisc.decreaseChance = nil
		qdisc.decreaseChanceUtilisationReducer = nil
		return
	end

	if ping.current < ping.limit then
		qdisc.decreaseChanceBaseline = 0
		qdisc.decreaseChance = 0
		qdisc.decreaseChanceUtilisationReducer = 0
		return
	end

	local baseline = (
			qdisc.stable * 0.7
			+ qdisc.mean * 0.3
			+ qdisc.shortPeak * qdisc.bandwidthTarget * 0.9
			+ qdisc.longPeak * qdisc.bandwidthTarget * 0.1
		) * 0.5
	qdisc.decreaseChanceBaseline = (qdisc.rate - baseline) / baseline

	if qdisc.rate > qdisc.bandwidth then
		qdisc.decreaseChanceUtilisationReducer = (qdisc.bandwidth / qdisc.rate) ^ 4
	else
		qdisc.decreaseChanceUtilisationReducer = 1
	end
	qdisc.decreaseChance = qdisc.decreaseChanceBaseline * qdisc.decreaseChanceUtilisationReducer

	if qdisc.cooldown == 0 then
		qdisc.decreaseChance = qdisc.decreaseChance * 0.5
	end
end

local function adjustDecreaseChances()
	if
		not egress.decreaseChance
		or not ingress.decreaseChance
		or egress.decreaseChance <= 0
		or ingress.decreaseChance <= 0
	then
		return
	end

	if egress.decreaseChanceUtilisationReducer > ingress.decreaseChanceUtilisationReducer then
		egress.decreaseChance = egress.decreaseChance * ingress.decreaseChanceUtilisationReducer
	elseif egress.decreaseChanceUtilisationReducer < ingress.decreaseChanceUtilisationReducer then
		ingress.decreaseChance = ingress.decreaseChance * egress.decreaseChanceUtilisationReducer
	end

	if egress.decreaseChance < ingress.decreaseChance then
		egress.decreaseChance = egress.decreaseChance * (egress.decreaseChance / ingress.decreaseChance) ^ 15
	elseif egress.decreaseChance > ingress.decreaseChance then
		ingress.decreaseChance = ingress.decreaseChance * (ingress.decreaseChance / egress.decreaseChance) ^ 15
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

	if qdisc.decreaseChance and qdisc.decreaseChance > 0 then
		qdisc.cooldown = qdisc.cooldown + interval
		return
	end

	if ping.current < ping.target and qdisc.cooldown > 0 then
		qdisc.cooldown = qdisc.cooldown - interval
	end
end

local function calculateDecrease(qdisc)
	if qdisc.decreaseChance > 1 then
		qdisc.decreaseChance = 1
	end

	qdisc.change = (qdisc.bandwidth - qdisc.rate * (1 + qdisc.bandwidthTarget) * 0.5) * qdisc.decreaseChance * -1
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

	if qdisc.decreaseChance and qdisc.decreaseChance > 0 and qdisc.rate > qdisc.minimum then
		calculateDecrease(qdisc)
		return
	end

	if
		ping.current < ping.target
		and qdisc.cooldown == 0
		and ping.clear >= stableSeconds
		and (qdisc.stable > qdisc.bandwidth * 0.98 or math.random(1, 100) <= 50 * interval)
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

	if
		tc[1].kind ~= "cake"
		or not tonumber(tc[1].options.bandwidth)
		or not tc[1].handle
		or not tonumber(tc[1].options.rtt)
	then
		qdisc.bandwidth = nil
		qdisc.handle = nil
		qdisc.kind = nil
		qdisc.rtt = nil
		return
	end

	qdisc.bandwidth = tc[1].options.bandwidth * 0.008
	qdisc.handle = tc[1].handle
	qdisc.kind = tc[1].kind
	qdisc.rtt = tc[1].options.rtt * 0.001
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

	local ingressRate = 0
	local ingressUtilisation = 0
	local ingressBandwidth = 0
	local ingressDecreaseChance = 0
	local ingressdecreaseChanceUtilisationReducer = 0
	local ingressDecreaseChanceBaseline = 0
	local egressRate = 0
	local egressUtilisation = 0
	local egressBandwidth = 0
	local egressDecreaseChance = 0
	local egressdecreaseChanceUtilisationReducer = 0
	local egressDecreaseChanceBaseline = 0

	if ingress.bandwidth then
		ingressRate = ingress.rate
		ingressUtilisation = ingress.utilisation
		ingressBandwidth = ingress.bandwidth
		ingressDecreaseChanceBaseline = ingress.decreaseChanceBaseline
		ingressdecreaseChanceUtilisationReducer = ingress.decreaseChanceUtilisationReducer
		ingressDecreaseChance = ingress.decreaseChance
	end
	if egress.bandwidth then
		egressRate = egress.rate
		egressUtilisation = egress.utilisation
		egressBandwidth = egress.bandwidth
		egressDecreaseChanceBaseline = egress.decreaseChanceBaseline
		egressdecreaseChanceUtilisationReducer = egress.decreaseChanceUtilisationReducer
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
		.. string.format("%.2f", ingressRate)
		.. ";	"
		.. string.format("%.2f", egressRate)
		.. ";	"
		.. string.format(
			"%.2f",
			ingressDecreaseChanceBaseline * ingressdecreaseChanceUtilisationReducer
		)
		.. ";	"
		.. string.format("%.2f", ingressDecreaseChance)
		.. ";	"
		.. string.format(
			"%.2f",
			egressDecreaseChanceBaseline * egressdecreaseChanceUtilisationReducer
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

	if not ping.current and ingress.rate == 0 then
		interfaceReconnect(interface)
		writeStatus()
		return
	end

	if not ping.current then
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
		pingResponseCount = pingResponseCount + 1

		local pingResponseTime = tonumber(string.match(line, "time=(%d+%.?%d*)"))
		if pingResponseTime then
			table.insert(pingResponseTimes, pingResponseTime)
		end

		if pingResponseCount < hostsCount then
			return
		end

		if #pingResponseTimes > 0 then
			pingStatus = 0
			ping.current = math.min(unpack(pingResponseTimes))
		else
			pingStatus = 1
			ping.current = nil
		end

		statisticsInterval()
		pingResponseCount = 0
		pingResponseTimes = {}
		retriesRemaining = retries
	elseif string.find(line, "Adding host .* failed: ") then
		log("LOG_WARNING", line)
		hostsCount = hostsCount - 1
		pingStatus = 4
	elseif string.find(line, "ping_send failed: No such device") then
		pingStatus = 4
	elseif
		string.find(line, "^Hangup$")
		or string.find(line, "^Killed$")
		or string.find(line, "^Terminated$")
		or string.find(line, " packets transmitted, .* received, .* packet loss, time .*ms")
	then
		pingStatus = 3
	elseif string.find(line, "ping_send failed: ") then
		pingStatus = 2
	elseif string.find(line, "Invalid QoS argument:") then
		log("LOG_ERR", "Invalid dscp config value specified for " .. interface)
		exit()
	elseif string.find(line, "ping_sendto: Permission denied") then
		log("LOG_ERR", "Unable to ping remote hosts on " .. interface .. " (" .. device .. ")")
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

	hostsCount = #hosts
	intervalEpoch = nil
	ping = {}
	pingResponseCount = 0
	pingResponseTimes = {}
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
			log("LOG_WARNING", "Invalid interval config value specified for " .. interface)
		else
			interval = config.interval
		end
	end

	if config.iptype and config.iptype ~= "ipv4" and config.iptype ~= "ipv6" and config.iptype ~= "ipv4v6" then
		log("LOG_WARNING", "Invalid iptype config value specified for " .. interface)
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
			log("LOG_WARNING", "Invalid hosts list specified for " .. interface)
		else
			hosts = config.hosts
		end
	end

	if config.reconnect then
		config.reconnect = toboolean(config.reconnect)
		if config.reconnect == nil then
			log("LOG_WARNING", "Invalid reconnect config value specified for " .. interface)
		else
			reconnect = config.reconnect
		end
	end

	if config.autorate then
		config.autorate = toboolean(config.autorate)
		if config.autorate == nil then
			log("LOG_WARNING", "Invalid autorate config value specified for " .. interface)
		else
			autorate = config.autorate
		end
	end

	if readArg("v", "verbose") then
		verbose = true
	elseif config.verbose then
		config.verbose = toboolean(config.verbose)
		if config.verbose == nil then
			log("LOG_WARNING", "Invalid verbose config value specified for " .. interface)
		else
			verbose = config.verbose
		end
	end

	if readArg("l", "log") then
		logFile = readArg("l", "log")
	elseif config.logFile then
		if not string.find(config.logFile, "^/[^%$]*$") then
			config.logFile = nil
		end
		if config.logFile == nil then
			log("LOG_WARNING", "Invalid logFile config value specified for " .. interface)
		else
			logFile = config.logFile
		end
	end

	if logFile then
		os.remove(logFile)
	end

	console = readArg("c", "console")

	if not autorate then
		return
	end

	pingIncreasePersistence = 0.985
	pingDecreasePersistence = 0.05
	shortPeakPersistence = 0.25
	longPeakPersistence = 0.99
	pingPersistence = 0.99
	stablePersistence = 0.9
	stableSeconds = 2
	egress.bandwidthTarget = 0.8
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
			log("LOG_WARNING", "Invalid shortPeakPersistence config value specified for " .. interface)
		else
			shortPeakPersistence = config.shortPeakPersistence
		end
	end

	if config.longPeakPersistence then
		config.longPeakPersistence = tonumber(config.longPeakPersistence)
		if not config.longPeakPersistence or config.longPeakPersistence <= 0 or config.longPeakPersistence > 1 then
			log("LOG_WARNING", "Invalid longPeakPersistence config value specified for " .. interface)
		else
			longPeakPersistence = config.longPeakPersistence
		end
	end

	if config.pingPersistence then
		config.pingPersistence = tonumber(config.pingPersistence)
		if not config.pingPersistence or config.pingPersistence <= 0 or config.pingPersistence > 1 then
			log("LOG_WARNING", "Invalid pingPersistence config value specified for " .. interface)
		else
			pingPersistence = config.pingPersistence
		end
	end

	if config.stablePersistence then
		config.stablePersistence = tonumber(config.stablePersistence)
		if not config.stablePersistence or config.stablePersistence <= 0 or config.stablePersistence > 1 then
			log("LOG_WARNING", "Invalid stablePersistence config value specified for " .. interface)
		else
			stablePersistence = config.stablePersistence
		end
	end

	if config.stableSeconds then
		config.stableSeconds = tonumber(config.stableSeconds)
		if not config.stableSeconds or config.stableSeconds <= 0 then
			log("LOG_WARNING", "Invalid stableSeconds config value specified for " .. interface)
		else
			stableSeconds = config.stableSeconds
		end
	end

	if config.egressTarget then
		config.egressTarget = tonumber(config.egressTarget)
		if not config.egressTarget or config.egressTarget <= 0 or config.egressTarget > 1 then
			log("LOG_WARNING", "Invalid egressTarget config value specified for " .. interface)
		else
			egress.bandwidthTarget = config.egressTarget
		end
	end

	if config.ingressTarget then
		config.ingressTarget = tonumber(config.ingressTarget)
		if not config.ingressTarget or config.ingressTarget <= 0 or config.ingressTarget > 1 then
			log("LOG_WARNING", "Invalid ingressTarget config value specified for " .. interface)
		else
			ingress.bandwidthTarget = config.ingressTarget
		end
	end

	if config.rtt then
		config.rtt = tonumber(config.rtt)
		if not config.rtt or config.rtt <= 0 then
			log("LOG_WARNING", "Invalid rtt config value specified for " .. interface)
		else
			rtt = config.rtt
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
		if pingStatus ~= 2 and pingStatus ~= 3 then
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
