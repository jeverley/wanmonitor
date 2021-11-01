--[[
Copyright 2021 Jack Everley
Lua script for monitoring a wan interface and auto-adjusting its qdiscs' bandwidth for SQM
Command line arguments:
	required	-i	(--interface)	Used to specify the wan interface to monitor
	optional	-s	(--status)		Used to specify a status file path
	optional	-c	(--console)		Used to run attached to an interactive console
]]

local jsonc = require("luci.jsonc")
local signal = require("posix.signal")
local syslog = require("posix.syslog")
local systime = require("posix.sys.time")
local unistd = require("posix.unistd")

local verbose
local appendStatus
local console
local egress
local ingress
local interface
local pid
local pidFile
local cpid
local ping
local pingStatus
local statusFile

local device
local dscp
local hosts
local interval
local iptype
local bandwidthTarget
local maximumPersistence
local pingPersistence
local stablePersistence
local assuredPeriod
local reconnect
local autorate

local hostsCount
local pingResponseCount
local pingResponseTimes
local retries
local retriesRemaining
local previousRxBytes
local previousTxBytes
local previousEpoch

local function log(priority, message)
	if console then
		print(priority .. ": " .. message)
		return
	end
	syslog.openlog("wanmonitor", syslog.LOG_PID, syslog.LOG_DAEMON)
	syslog.syslog(syslog[priority], message)
	syslog.closelog()
end

local function cleanup()
	if cpid then
		signal.kill(cpid, signal.SIGKILL)
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

local function mean(values)
	return sum(values) / #values
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

local function movingMean(sample, value, period)
	table.insert(sample, value)
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

local function updatePingStatistics(qdisc)
	if not qdisc.kind then
		qdisc.ping = nil
		return
	end

	if not qdisc.ping then
		qdisc.ping = {}
		qdisc.ping.clear = 0
		qdisc.ping.latent = 0
	end

	local limit = qdisc.rtt * 1.05
	if not qdisc.ping.limit or ping < limit then
		qdisc.ping.limit = limit
	else
		qdisc.ping.limit = qdisc.ping.limit * pingPersistence + ping * (1 - pingPersistence)
	end

	if not qdisc.ping.minimum or qdisc.ping.minimum > qdisc.ping.limit then
		qdisc.ping.minimum = qdisc.ping.limit
	end
	if ping < qdisc.ping.minimum then
		qdisc.ping.minimum = ping
	else
		qdisc.ping.minimum = qdisc.ping.minimum * pingPersistence + qdisc.ping.limit * (1 - pingPersistence)
	end

	qdisc.ping.target = qdisc.ping.minimum
		+ (qdisc.ping.limit - qdisc.ping.minimum) * (qdisc.ping.minimum / qdisc.ping.limit) ^ 0.7

	if ping > qdisc.ping.limit then
		qdisc.ping.clear = 0
		qdisc.ping.latent = qdisc.ping.latent + interval
		return
	end

	if ping > qdisc.ping.target then
		return
	end

	qdisc.ping.clear = qdisc.ping.clear + interval
	qdisc.ping.latent = 0
end

local function updateRateStatistics(qdisc)
	if not qdisc.kind then
		qdisc.maximum = nil
		qdisc.minimum = nil
		qdisc.peak = nil
		qdisc.stable = nil
		qdisc.assuredSample = nil
		qdisc.target = nil
		return
	end

	local assured
	if ping < qdisc.ping.target then
		assured = qdisc.rate
	else
		assured = qdisc.rate * qdisc.bandwidthTarget
	end
	if not qdisc.assuredSample then
		qdisc.assuredSample = {}
	end
	local assuredMean = movingMean(qdisc.assuredSample, assured, assuredPeriod)

	if not qdisc.stable or ping < qdisc.ping.target then
		qdisc.stable = assuredMean
	else
		qdisc.stable = qdisc.stable * stablePersistence + assuredMean * (1 - stablePersistence)
	end

	if not qdisc.maximum or qdisc.rate > qdisc.maximum then
		qdisc.maximum = qdisc.rate
	else
		qdisc.maximum = qdisc.maximum * maximumPersistence + qdisc.rate * (1 - maximumPersistence)
	end

	if not qdisc.peak or qdisc.rate > qdisc.peak then
		qdisc.peak = qdisc.rate
	end

	qdisc.minimum = math.max(qdisc.maximum * 0.25, qdisc.stable, qdisc.peak * 0.01)
	qdisc.target = math.max(qdisc.bandwidth * qdisc.bandwidthTarget, qdisc.peak * qdisc.bandwidthTarget)
end

local function calculateDecreaseChance(qdisc)
	if not qdisc.kind then
		qdisc.decreaseChance = nil
		return
	end

	if ping < qdisc.ping.limit then
		qdisc.decreaseChance = 0
		return
	end

	local baseline = (qdisc.stable + qdisc.maximum * qdisc.bandwidthTarget * 0.9 + qdisc.target * 0.1) * 0.5
	qdisc.decreaseChance = (qdisc.rate - baseline) / baseline
end

local function amplifyDecreaseChanceDelta()
	if
		not egress.decreaseChance
		or not ingress.decreaseChance
		or egress.decreaseChance <= 0
		or ingress.decreaseChance <= 0
		or egress.decreaseChance == ingress.decreaseChance
	then
		return
	end

	if ingress.decreaseChance < egress.decreaseChance then
		ingress.decreaseChance = ingress.decreaseChance * (ingress.decreaseChance / egress.decreaseChance) ^ 15
	else
		egress.decreaseChance = egress.decreaseChance * (egress.decreaseChance / ingress.decreaseChance) ^ 15
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

	if ping < qdisc.ping.target and qdisc.cooldown > 0 then
		qdisc.cooldown = qdisc.cooldown - interval
	end
end

local function calculateDecrease(qdisc)
	local pingMultiplier = 1 - (qdisc.ping.limit / ping) ^ qdisc.ping.latent

	qdisc.change = (qdisc.bandwidth - qdisc.maximum * qdisc.bandwidthTarget)
		* interval
		* pingMultiplier
		* qdisc.decreaseChance
		* -1
	if qdisc.bandwidth + qdisc.change < qdisc.minimum then
		qdisc.change = qdisc.minimum - qdisc.bandwidth
	end

	if qdisc.change > -0.008 then
		qdisc.change = 0
	end
end

local function calculateIncrease(qdisc)
	local pingMultiplier = 1 - ping / qdisc.ping.target

	local targetMultiplier = qdisc.target / qdisc.bandwidth
	if targetMultiplier < 1 then
		targetMultiplier = targetMultiplier ^ 25
	end

	qdisc.change = qdisc.bandwidth * 0.025 * interval * pingMultiplier * targetMultiplier

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
		ping < qdisc.ping.target
		and qdisc.cooldown == 0
		and (qdisc.ping.clear >= 10 or qdisc.ping.clear >= 2 and qdisc.stable > qdisc.bandwidth * 0.98)
		and math.random(1, 100) <= 25
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

	if tc[1].handle ~= qdisc.handle then
		qdisc.target = nil
	end

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

local function adjustSqm()
	if not autorate or not egress.rate or not ingress.rate then
		return
	end

	getQdisc(egress)
	getQdisc(ingress)

	updatePingStatistics(egress)
	updatePingStatistics(ingress)

	updateRateStatistics(egress)
	updateRateStatistics(ingress)

	calculateDecreaseChance(egress)
	calculateDecreaseChance(ingress)
	amplifyDecreaseChanceDelta()

	updateCooldown(egress)
	updateCooldown(ingress)

	calculateChange(egress)
	calculateChange(ingress)

	updateQdisc(egress)
	updateQdisc(ingress)
end

local function writeStatus()
	local mode
	if appendStatus then
		mode = "a"
	end

	if verbose then
		writeFile(
			statusFile,
			jsonc.stringify({
				interface = interface,
				device = device,
				ping = ping,
				egress = egress,
				ingress = ingress,
			}),
			mode
		)
		return
	end

	writeFile(
		statusFile,
		jsonc.stringify({
			interface = interface,
			device = device,
			ping = ping,
			egress = {
				device = egress.device,
				target = egress.target,
				bandwidth = egress.bandwidth,
				peak = egress.peak,
				maximum = egress.maximum,
				rate = egress.rate,
				stable = egress.stable,
				decreaseChance = egress.decreaseChance,
				change = egress.change,
			},
			ingress = {
				device = ingress.device,
				target = ingress.target,
				bandwidth = ingress.bandwidth,
				peak = ingress.peak,
				maximum = ingress.maximum,
				rate = ingress.rate,
				stable = ingress.stable,
				decreaseChance = ingress.decreaseChance,
				change = ingress.change,
			},
		}),
		mode
	)
end

local function statisticsInterval()
	local txBytes = tonumber(readFile("/sys/class/net/" .. device .. "/statistics/tx_bytes"))
	local rxBytes = tonumber(readFile("/sys/class/net/" .. device .. "/statistics/rx_bytes"))
	local intervalEpoch = epoch()

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

	if not ping and ingress.rate == 0 then
		interfaceReconnect(interface)
		writeStatus()
		return
	end

	if not ping then
		ping = interval * 1000
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
			ping = median(pingResponseTimes)
		else
			pingStatus = 1
			ping = nil
		end

		statisticsInterval()
		pingResponseCount = 0
		pingResponseTimes = {}
		retriesRemaining = retries
	elseif string.find(line, "Adding host .* failed: ") then
		hostsCount = hostsCount - 1
		pingStatus = 5
	elseif string.find(line, "ping_send failed: No such device") then
		pingStatus = 5
	elseif string.find(line, "^Hangup$") or string.find(line, "^Killed$") or string.find(line, "^Terminated$") then
		pingStatus = 4
	elseif string.find(line, " packets transmitted, .* received, .* packet loss, time .*ms") then
		pingStatus = 4
	elseif string.find(line, "Usage: oping ") then
		pingStatus = 3
	elseif string.find(line, "ping_send failed: ") then
		pingStatus = 2
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
	ping = nil
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
	cpid = execute("pgrep -n -x oping -P " .. pid)

	repeat
		local line = fd:read("*line")
		processPingOutput(line)
	until not line
	fd:close()
	cpid = nil
end

local function initialise()
	console = readArg("c", "console")
	if console and console ~= true then
		log("LOG_ERR", "Properties must not be specified for the -c (--console) argument")
		os.exit()
	end

	interface = readArg("i", "interface")
	if type(interface) ~= "string" or interface == "" then
		log("LOG_ERR", "An interface must be specified for the -i (--interface) argument")
		os.exit()
	end

	statusFile = readArg("s", "status")
	if statusFile == true then
		log("LOG_ERR", "A filepath must be specified for the -s (--status) argument")
		os.exit()
	elseif not statusFile then
		statusFile = "/var/wanmonitor." .. interface .. ".json"
	end

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
	reconnect = false
	retries = 2
	autorate = false
	verbose = false
	appendStatus = false

	if config.dscp then
		dscp = config.dscp
	end

	if tonumber(config.interval) and config.interval > 0 then
		interval = config.interval
	end

	if config.iptype and config.iptype ~= "ipv4" and config.iptype ~= "ipv6" then
		log("LOG_WARNING", "Invalid iptype specified for " .. interface)
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
		hosts = config.hosts
	end

	if config.reconnect then
		reconnect = toboolean(config.reconnect)
	end

	if config.autorate then
		autorate = toboolean(config.autorate)
	end

	if config.verbose then
		verbose = toboolean(config.verbose)
	end

	if config.appendStatus then
		appendStatus = toboolean(config.appendStatus)
	end

	if not autorate then
		return
	end

	bandwidthTarget = 0.95
	maximumPersistence = 0.25
	pingPersistence = 0.99
	stablePersistence = 0.9
	assuredPeriod = 2

	egress.device = device

	if toboolean(config.veth) then
		ingress.device = "veth" .. string.sub(interface, 1, 11)
	elseif not config.ingressDevice or device == config.ingressDevice then
		ingress.device = "ifb4" .. string.sub(device, 1, 11)
	else
		ingress.device = config.ingressDevice
	end

	if tonumber(config.maximumPersistence) then
		maximumPersistence = tonumber(config.maximumPersistence)
	end

	if tonumber(config.pingPersistence) then
		pingPersistence = tonumber(config.pingPersistence)
	end

	if tonumber(config.stablePersistence) then
		stablePersistence = tonumber(config.stablePersistence)
	end

	if tonumber(config.egressTarget) then
		egress.bandwidthTarget = tonumber(config.egressTarget)
	else
		egress.bandwidthTarget = bandwidthTarget
	end

	if tonumber(config.ingressTarget) then
		ingress.bandwidthTarget = tonumber(config.ingressTarget)
	else
		ingress.bandwidthTarget = bandwidthTarget
	end

	maximumPersistence = maximumPersistence ^ interval
	pingPersistence = pingPersistence ^ interval
	stablePersistence = stablePersistence ^ interval
	assuredPeriod = assuredPeriod / interval
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
	signal.signal(signal.SIGTERM, exit)

	if not console then
		daemonise()
	end
	pid = unistd.getpid()
	writeFile(pidFile, pid)
	log("LOG_NOTICE", "Started for " .. interface .. " (" .. device .. ")")

	retriesRemaining = retries
	while retriesRemaining > 0 do
		pingLoop()
		if pingStatus == 5 then
			interfaceReconnect(interface)
		end
		if pingStatus ~= 2 and pingStatus ~= 4 then
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
