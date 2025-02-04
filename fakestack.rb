#!/usr/bin/env ruby
# Go get PacketFu and PcapRub at http://code.google.com/p/packetfu
require 'packetfu'
# USAGE: sudo fakestack.rb eth0 8080
$iface = ARGV[0] || "eth0"
$port = (ARGV[1] || 8080).to_i
puts "Watching for SYNs on #{$iface} to #{$port}..."
cap = PacketFu::Capture.new(:iface => $iface, :start => true, :filter => "tcp
and dst port #{$port}")
$config = PacketFu::Utils.whoami?(:iface => $iface)
$http_payload = "PGh0bWw+PGJvZHk+CjxwPjxpPlRoaXMgd2FzIGEgdHJpdW1waCw8YnI+Ckkn\n"+
"bSBtYWtpbmcgYSBub3RlIGhlcmU6IEhVR0UgU1VDQ0VTUy48YnI+CihJdCdz\n"+
"IGhhcmQgdG8gb3ZlcnN0YXRlIG15IHNhdGlzZmFjdGlvbi4pCjwvaT48L3A+\n"+
"CjwvYm9keT48L2h0bWw+Cg==\n"
$http_response =<<EOF
HTTP/1.0 200 Ok\r
Server: micro_httpd\r
Date: #{Time.now.gmtime}\r
Content-Type: text/html; utf-8\r
Content-Length: #{$http_payload.unpack("m").first.size}\r
Last-Modified: #{Time.now.gmtime}\r
Connection: close\r
\r
#{$http_payload.unpack("m").first}
EOF

puts "Listening on port #{$port}..."
loop do
$established = false
$disconnected = false
$http_sent = false
puts "Setting up the fake stack..."
while($disconnected == false) do
  cap.stream.each do |pkt|
   packet = PacketFu::Packet.parse pkt
   # Establish a session.
   if packet.tcp_flags.syn == 1 && !$established
   	if packet.tcp_flags.ack == 0
       puts "Got a SYN with seq = #{seq = packet.tcp_seq} from #{packet.ip_saddr}"
       puts "Generating packets..."
       ack_packet = PacketFu::TCPPacket.new(:config => $config)
       ack_packet.ip_daddr= packet.ip_saddr
       ack_packet.tcp_src = $port
       ack_packet.tcp_dst = packet.tcp_src
       ack_packet.tcp_ack = seq + 1
       puts "Duping and splitting SYN and ACK..."
       syn_packet = ack_packet.dup
       ack_packet.tcp_flags.syn = 0
       ack_packet.tcp_flags.ack = 1
       ack_packet.recalc
       # Comment out the next two lines to avoid sending the ack.
       puts "Sending ACK..."
       ack_packet.to_w($iface)
       syn_packet.tcp_flags.urg = 0
       syn_packet.tcp_flags.ack = 0
       syn_packet.tcp_flags.psh = 0
       syn_packet.tcp_flags.rst = 0
       syn_packet.tcp_flags.syn = 1
       syn_packet.tcp_flags.fin = 0
       syn_packet.tcp_ack = 0
       syn_packet.tcp_seq = rand(0xffffffff)+1 # New sequence number
       syn_packet.recalc
       puts "Sending SYN..."
       syn_packet.to_w($iface)
   else
	 	puts "Got a SYNACK with seq = #{seq = packet.tcp_seq} from #{packet.ip_saddr}"
		ack_packet = PacketFu::TCPPacket.new(:config => $config)
       	ack_packet.ip_daddr = packet.ip_saddr
       	ack_packet.tcp_src = $port
	ack_packet.tcp_dst = packet.tcp_src
       	ack_packet.tcp_ack = seq + 1
       	ack_packet.tcp_seq = packet.tcp_ack
       	ack_packet.tcp_flags.ack = 1
       	ack_packet.recalc
       	puts "Acking the SYNACK. The handshake's a LIE!"
       	ack_packet.to_w($iface)
       	$established = true
       end
   elsif $established && !$http_sent
   	if packet.tcp_flags.ack == 1
   		if packet.tcp_flags.psh == 1
   			puts "Got a PSH/ACK with seq = #{seq = packet.tcp_seq}, probably the GET..."
   			puts packet.payload.inspect
   			ack_packet = PacketFu::TCPPacket.new(:config => $config) 
                        ack_packet.ip_daddr = packet.ip_saddr
   			ack_packet.tcp_src = $port
   			ack_packet.tcp_dst = packet.tcp_src
   			ack_packet.tcp_ack = seq + packet.payload.size
   			ack_packet.tcp_seq = packet.tcp_ack
   			# Normal people: One packet GET
   			# # IE8: Two packet GET, break right before the Keep-Alive.
   			# # IE6: Three packets, it screws me up at the moment. Just use Firefox. 
   			if packet.payload.size > 0 # Thanks for the 2 packet GET, IE.
   				ack_packet.tcp_flags.ack = 1
   				ack_packet.recalc
   				puts "Acking the GET..."
   				ack_packet.to_w($iface)
   				http_packet = ack_packet.dup
   				http_packet.payload = $http_response[0,1400] # Enforce a max size. http_packet.recalc
   				puts "Delivering the payload..."
   				http_packet.to_w($iface)
   				$http_sent = true
   			end
   		end
   	end
   elsif $http_sent
   	if packet.tcp_flags.rst == 0
   		puts "Payload ack'ed with seq = #{seq = packet.tcp_seq}. RSTing, since FINs are for chumps."
   		rst_packet = PacketFu::TCPPacket.new(:config => $config)
   		rst_packet.ip_daddr = packet.ip_saddr
   		rst_packet.tcp_src = $port
   		rst_packet.tcp_dst = packet.tcp_src
   		rst_packet.tcp_ack = seq
   		rst_packet.tcp_seq = packet.tcp_ack
   		rst_packet.tcp_flags.rst = 1
   		rst_packet.tcp_flags.ack = 1
   		$disconnected = true
   		rst_packet.recalc
   		puts "Sent a RST"
   		rst_packet.to_w($iface)
   	else # Got a RST, thanks!
   		$disconnected = true
end
end
end
end
end
