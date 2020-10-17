local M = require 'posix'.sys.socket
ifnet = require'libluaknet'

local sleep = require'posix'.unistd.sleep
local sock_close = require'posix'.unistd.close

local dhcp_resolv_file = '/tmp/resolv.conf'
local dhcp_ntpd_file = '/tmp/ntpd.conf'

local dhcp_server_port = 67
local dhcp_client_port = 68

local dhcp_op = string.char(0x01);
local dhcp_htype = string.char(0x01);
local dhcp_hlen = string.char(0x06);
local dhcp_hops = string.char(0x00);
local dhcp_secs = string.char(0x00,0x00);
local dhcp_flags = string.char(0x80, 0x00);
local dhcp_ciaddr = string.char(0x00,0x00,0x00,0x00);
local dhcp_yiaddr = string.char(0x00,0x00,0x00,0x00);
local dhcp_siaddr = string.char(0x00,0x00,0x00,0x00);
local dhcp_giaddr = string.char(0x00,0x00,0x00,0x00);
local dhcp_chaddr_padding = string.char(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

local dhcp_sname = string.char(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

local dhcp_file = string.char(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

local dhcp_magic = string.char(0x63,0x82,0x53,0x63);
local dhcp_end = string.char(0xff);

local dhcp_timeout = 10;
local dhcp_request_count = 5

local dhcp_option_submask = 0x01;
local dhcp_option_dmn_nameserver = 0x06;
local dhcp_option_domain = 0x0f;
local dhcp_option_def_route = 0x03;
local dhcp_option_req_ip = 0x32;
local dhcp_option_lease_time = 0x33;
local dhcp_option_msg = 0x35;
local dhcp_option_srv_ip = 0x36;
local dhcp_option_req_list = 0x37;
local dhcp_option_t1 = 0x40;
local dhcp_option_t2 = 0x41;
local dhcp_option_ntp = 0x2a;

local dhcp_msg_discover = 0x01;
local dhcp_msg_offer = 0x02;
local dhcp_msg_request = 0x03;
local dhcp_msg_ack = 0x05;
local dhcp_msg_nak = 0x06;


local function dhcp_var_dump_msg(data)
	if data then
		l = #data
		i = 1
		while i <= l do
			io.write(string.format("%02x", data:byte(i))..' ')
			i = i + 1
		end
		io.write('\n')
	end
	io.write('\n')
	
end

local function dhcp_gen_xid()
	return string.char(math.random(48,119), math.random(48,119), math.random(48,119), math.random(48,119))
end

local function dhcp_iface_get_mac(iface)
	local info = ifnet.info(iface)
	if not info then
		return nil
	end
	local mac = info[iface].mac
	local s, n = ''
	for n in mac:gmatch('[^:]+') do
		s = s.. string.char(tonumber(n,16))
	end
	return s
end

local function dhcp_set_ip(iface, ip, mask)
	ifnet.clear(iface)
	return ifnet.setip(iface, 4, ip, mask)
end

local function dhcp_find_option(data, opt)
	if not data then
		return nil
	end
	local i,j = data:find(dhcp_magic)
	if not i then
		return nil
	end
	j = j + 1
	local s = ''
	while j <= #data do
			if data:byte(j) == opt then
				local len = data:byte(j + 1)
				s = data:sub(j + 2, j + len + 1)
				break;
			end
		j = j + 1
		n = data:byte(j)
		for i = 1,n do
			j = j + 1
		end
		j = j + 1
		if data:byte(j) == opt then
			local len = data:byte(j + 1)
			s = data:sub(j + 2, j + len + 1)
			break;
		end
	end
	if #s == 0 then
		return nil
	end
	return s
end

local function dhcp_option_to_table(opt, len)
	if not opt then
		return {}
	end
	local data = {}

	local n = 1

	for i = 1, #opt, len do
		data[n] = opt:sub(i, len + i - 1)
		n = n + 1
	end 

	return data
end

local function dhcp_form_msg(xid, mac, msg_type, ar) -- ar: ciaddr, req_ip, server_ip, secs, flags, req_list
	local msg = dhcp_op .. dhcp_htype .. dhcp_hlen .. dhcp_hops .. xid
	msg = msg .. (ar.secs or dhcp_secs) .. (ar.flags or dhcp_flags) .. (ar.ciaddr or dhcp_ciaddr)
	msg = msg .. dhcp_yiaddr .. dhcp_siaddr .. dhcp_giaddr .. mac
	msg = msg .. dhcp_chaddr_padding .. dhcp_sname .. dhcp_file .. dhcp_magic
	msg = msg .. string.char(dhcp_option_msg, 0x01, msg_type)
	if ar.req_ip then
		msg = msg .. string.char(dhcp_option_req_ip, 0x04) .. ar.req_ip
	end
	if ar.server_ip then
		msg = msg .. string.char(dhcp_option_srv_ip, 0x04) .. ar.server_ip
	end
	if ar.req_list then
		local count,msg_list,k,v = 0, ''
		for k,v in pairs(ar.req_list) do
			count = count + 1
			msg_list = msg_list .. string.char(v)
		end
		if count > 0 then
			msg = msg .. string.char(dhcp_option_req_list, count) .. msg_list
		end
	end
	msg = msg .. dhcp_end
	return msg
end

local function dhcp_open_socket(ip, port)
	local fd, err = M.socket(M.AF_INET, M.SOCK_DGRAM, M.IPPROTO_UDP)
	if not fd then
		return nil
	end
	local ok
	if ip == '0.0.0.0' then
		ok, err = M.setsockopt(fd, M.SOL_SOCKET, M.SO_BROADCAST, 1)
		if not ok then
			return nil
		end
	end
	ok, err = M.setsockopt(fd, M.SOL_SOCKET, M.SO_SNDTIMEO, dhcp_timeout, 0)
	if not ok then
		return nil
	end
	ok, err = M.setsockopt(fd, M.SOL_SOCKET, M.SO_RCVTIMEO, dhcp_timeout, 0)
	if not ok then
		return nil
	end
	ok, err = M.setsockopt(fd, M.SOL_SOCKET, M.SO_REUSEADDR, 1)
	if not ok then
		return nil
	end
	ok, err = M.bind(fd, {family=M.AF_INET, addr=ip, port=port})
	if not ok then
		return nil
	end
	return fd
end

local function dhcp_send_recv(fd, data, ip, port)
	local ok, err = M.sendto(fd, data, {family=M.AF_INET, addr=ip, port=port})
	if not ok then
		return nil
	end

	local data, sa = M.recvfrom(fd, 1024)
	if not data then
		return nil
	end
	return data
end

local function dhcp_xid_valid(xid, msg)
	local msg_xid = string.char(msg:byte(5), msg:byte(6), msg:byte(7), msg:byte(8))
	if xid == msg_xid then
		return true
	end
	return false
end

-- retrieves ciaddr or siaddr from data. returns ip in hex string
local function dhcp_get_addr(data, is_req)
	if not data then
		return nil
	end
	local n = 21
	if is_req then
		n = 17
	end
	local ip = data:sub(n, n + 3)
	-- local ip_dots = data:byte(n) .. '.' .. data:byte(n + 1) .. '.' .. data:byte(n + 2) .. '.' ..data:byte(n + 3)
	return ip--[[, ip_dots--]]
end

local function dhcp_ip_to_dot_ip(ip)
	local ip_dots = ip:byte(1) .. '.' .. ip:byte(2) .. '.' .. ip:byte(3) .. '.' ..ip:byte(4)
	return ip_dots
end

local function dhcp_get_time(ack, what)
	local opt = dhcp_find_option(ack, what)
	if not opt then
		return nil
	end
	local time = math.floor((tonumber(string.format("%02x%02x%02x%02x", opt:byte(1), opt:byte(2), opt:byte(3),opt:byte(4)), 16) + 2^31) % 2^32 - 2^31)
	return time
end

local function dhcp_state_re(re_type, xid, mac, exp_time, req_ip, s_ip, lease_time)
	local ip_dot = dhcp_ip_to_dot_ip(req_ip)
	local flags = dhcp_flags
	local msg_type, send_time, ack
	local send_ip, recv_ip = '255.255.255.255', '0.0.0.0'
	if re_type == 'new' then
		flags = string.char(0x00, 0x00)
		recv_ip = ip_dot
		send_ip = dhcp_ip_to_dot_ip(s_ip)
	end
	local request = dhcp_form_msg(xid, mac, dhcp_msg_request, {flags=flags, 
				ciaddr = req_ip, req_list = {dhcp_option_submask,
				dhcp_option_lease_time, dhcp_option_t1, dhcp_option_t2,
				dhcp_option_dmn_nameserver, dhcp_option_def_route, dhcp_option_domain, dhcp_option_ntp}
				})
	repeat
		fd = dhcp_open_socket(recv_ip, dhcp_client_port)
		if fd then
			send_time = os.time()
			ack = dhcp_send_recv(fd, request, send_ip, dhcp_server_port)
			if ack then
				if dhcp_xid_valid(xid, ack) then
					msg_type = dhcp_find_option(ack, dhcp_option_msg)
					if not msg_type then
						ack = nil
					else
						msg_type = msg_type:byte(1)
						if msg_type == dhcp_msg_ack then
							sock_close(fd)
							break
						end
						if msg_type == dhcp_msg_nak then
							sock_close(fd)
							return nil
						else
							ack = nil
						end
					end
				end
			end
			sock_close(fd)
		end
		sleep(1)
	until os.time() >= exp_time
	if ack then
		return ack, send_time
	end
	if re_type == 'new' then
		return dhcp_state_re('bind', xid, mac, lease_time, req_ip)
	end
	return nil

end

local function dhcp_state_bound(iface, xid, mac, ack, send_time)
	local s_ip = dhcp_get_addr(ack)
	local req_ip = dhcp_get_addr(ack, true)
	local raw_mask = dhcp_find_option(ack, dhcp_option_submask)
	local ip = dhcp_ip_to_dot_ip(req_ip)
	local mask = dhcp_ip_to_dot_ip(raw_mask)

	-- set resolv.conf
	local file = io.open(dhcp_resolv_file, 'w')
	if file then
		local domain = dhcp_find_option(ack, dhcp_option_domain)
		local name_srv = dhcp_find_option(ack, dhcp_option_dmn_nameserver)
		local tmp = dhcp_option_to_table(name_srv, 4)
		if domain then
			file:write('domain ' .. domain .. '\n')
		end
		for k,v in pairs(tmp) do 
			file:write('nameserver ' .. dhcp_ip_to_dot_ip(v) .. '\n')
		end
		io.close(file)
	end

	-- set ntp
	file = io.open(dhcp_ntpd_file, 'w')
	if file then
		local ntp = dhcp_find_option(ack, dhcp_option_ntp)
		local tmp = dhcp_option_to_table(ntp, 4)
		for k,v in pairs(tmp) do 
			file:write('ntp ' .. dhcp_ip_to_dot_ip(v) .. '\n')
		end
		io.close(file)
	end

	-- set ip
	dhcp_set_ip(iface, ip, mask)

	-- wait for t1 expire, and then go to renew state
	repeat
		local lease_time = dhcp_get_time(ack, dhcp_option_lease_time)
		local t1 = dhcp_get_time(ack, dhcp_option_t1)
		local t2 = dhcp_get_time(ack, dhcp_option_t2)

		if not t1 then
			t1 = math.floor(0.5 * lease_time)
		end
		if not t2 then
			t2 = math.floor(0.87 * lease_time)
		end
		while os.time() < send_time + t1 do
			sleep(1)
		end
		ack, send_time = dhcp_state_re('new', xid, mac, t2 + send_time, req_ip, s_ip, lease_time + send_time)
		if not ack then
			return nil
		end

	until false

end

local function dhcp_state_requesting(iface, xid, mac, s_ip, req_ip)
	local fd = dhcp_open_socket('0.0.0.0', dhcp_client_port)
	if not fd then
		return nil
	end

	local request = dhcp_form_msg(xid, mac, dhcp_msg_request, {req_ip = req_ip, server_ip = s_ip,
					req_list = {dhcp_option_submask, dhcp_option_lease_time, dhcp_option_t1, dhcp_option_t2,
								dhcp_option_dmn_nameserver, dhcp_option_def_route, dhcp_option_domain, dhcp_option_ntp}
					})

	local ack = nil
	local n, send_time = 0
	repeat
		send_time = os.time()
		ack = dhcp_send_recv(fd, request, '255.255.255.255', dhcp_server_port)
		if dhcp_xid_valid(xid, ack) then
			msg_type = dhcp_find_option(ack, dhcp_option_msg)
			if not msg_type then
				ack = nil
			else
				msg_type = msg_type:byte(1)
				if msg_type == dhcp_msg_ack then
					break
				end
				if msg_type == dhcp_msg_nak then
					sock_close(fd)
					return nil
				else
					ack = nil
				end
			end

			if not ack then
				sleep(1)
			end
			n = n + 1
		end
	until ack or n > dhcp_request_count

	sock_close(fd)
	if not ack then
		return nil
	end
	dhcp_state_bound(iface, xid, mac, ack, send_time)
end


local function dhcp_state_selecting(iface, xid, mac, offer)
	if not dhcp_xid_valid(xid, offer) then   -- TODO collect offers and choose 
		return nil
	end
	local msg_type = dhcp_find_option(offer, dhcp_option_msg)
	if not msg_type then
		return nil
	end
	msg_type = msg_type:byte(1)
	if msg_type ~= dhcp_msg_offer then
		return nil
	end

	local s_ip = dhcp_get_addr(offer)
	local req_ip = dhcp_get_addr(offer, true)
	dhcp_state_requesting(iface, xid, mac, s_ip, req_ip)
end

local function dhcp_state_init(iface, mac)
	local xid = dhcp_gen_xid()
	local msg = dhcp_form_msg(xid, mac, dhcp_msg_discover, {})
	local fd = dhcp_open_socket('0.0.0.0', dhcp_client_port)
	if not fd then
		return nil
	end

	sleep(math.random(1, 10))

	local data = dhcp_send_recv(fd, msg, '255.255.255.255', dhcp_server_port)
	sock_close(fd)
	if not data then
		return nil
	end

	dhcp_state_selecting(iface, xid, mac, data)

end

local function main( iface )
	math.randomseed(os.time())
	local mac = dhcp_iface_get_mac(iface)
	if not mac then
		return nil
	end
	while true do
		dhcp_set_ip(iface, '0.0.0.0', '0')
		dhcp_state_init(iface, mac)
		sleep(2)
	end
end


local dhcp_client = {}
dhcp_client.run = main
return dhcp_client