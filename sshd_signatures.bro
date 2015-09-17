#
#
# This is a central collection of all the policy based signatures i
#  used in the isshd policy.

redef SSHD_POLICY::alarm_remote_exec +=
	/sh -i/
	| /bash -i/;


redef SSHD_POLICY::input_trouble +=
        /set history=0/
        | /nessus/
        | /ettercap/
        | /dsniff/
        | /nfsshell/
        | /[ \t]rewt/
        | /eggdrop/
        | /\/bin\/eject/
        | /(shell|xploit)_?code/
        | /execshell/
        | /ff\.core/
        | /su[ \t]+(daemon|news|adm)/
        | /rm[ \t]+-rf[ \t]+secure/
        | /cd[ \t]+\/dev\/[a-zA-Z]{3}/
        | />\/etc\/passwd/
        | /#define NOP.*0x/
        | /printf\(\"overflowing/
        | /exec[a-z]*\(\"\/usr\/openwin/
        | /ping.*-s.*%d/
	| / sh-3.1#/
	| / sh-3.2#/
	| / sh-3.3#/
	| / sh-2.0#/
	| /LD_AUDIT/
        | /LD_AOUT_LIBRARY_PATH/
        | /LD_AOUT_PRELOAD/
        | /LD_DYNAMIC_WEAK/
        | /LD_ORIGIN_PATH/
	| /[\"\'].*\$ORIGIN.*[\"\']/
	| /getuid\.so.*xtxqtcmd/
	|  /rewt/
	| /eggdrop/
	| /(shell|xploit)_?code/
	| /execshell/
	| /unset[ \t]+(histfile|history|HISTFILE|HISTORY)/
	| /cd[ \t]+\/dev\/[a-zA-Z]{3}/
	| />\/etc\/passwd/
	| /#define NOP.*0x/
	# test to see if these generate too much noise
	| /setuid\(0\)/
	| /setgid\(0\)/
	# look for shells being execed in a c-code sort of way
	| /execl\(\"\/bin\/sh\"\, \"\/bin\/sh\", NULL\)/
	# another test for signal/noise
	| /open\(\"\/proc\/ksyms\", \"r\"\)/
	# somewhat oldschool, but often old is tried before new ....
	| /open\(\"\/dev\/(mem|kmem|oldmem|shmem)/
	# the old self-re-exec ...
	| /execl\(\"\/proc\/self\/exe\"/
	# common more last year
	| /selinux_ops|dummy_security_ops|capability_ops/
	| /[Xx][Hh][Ee3][Ll1][Ll1][Cc][Oo0[Dd][Ee]/
	| /SCOTTTEST_IN/;

redef SSHD_POLICY::output_trouble +=
          /^-r.s.*root.*\/bin\/(sh|csh|tcsh)/
        | /Jumping to address/
        | /Jumping Address/
        | /smashdu\.c/
        | /PATH_UTMP/
        | /Log started at =/
        | /^# \[root@/
        | /^-r.s.*root.*\/bin\/(time|sh|csh|tcsh|bash|ksh)/
        | /invisibleX/
        | /PATH_(UTMP|WTMP|LASTLOG)/
        | /(PATH|STAT):\ .*=>/
        | /----- \[(FIN|RST|DATA LIMIT|Timed Out)\]/
        | /IDLE TIMEOUT/
        | /DATA LIMIT/
        | /-- TCP\/IP LOG --/
        | /STAT: (FIN|TIMED_OUT) /
        | /(shell|xploit)_code/
        | /execshell/
        | /Daemon port\.\.\.\./
        | /BOT_VERSION/
        | /NICKCRYPT/
        | /\/etc\/\.core/
        | /exec.*\/bin\/newgrp/
        | /deadcafe/
        | /[ \/]snap\.sh/
        | /Secure atime,ctime,mtime/
        | /Can\'t fix checksum/
        | /Promisc Dectection/
        | /(cd \/; uname -a; pwd; id)/
        | /drw0rm/
        | /[ \t][Rr][Ee3][Ww][Tt][Ee3][Dd]/
        | /rpc\.sadmin/
        | /by Mixter/
	| /sendfile\(.*\)\;/
	| /wunderbar.emporium/
	| /pwnkernel/
	| /therebel/
	| /MAPPED ZERO PAGE\!/
	| /Error: suffix or operands invalid for `mov'/
	| /MooseCox/
	| /\.\/exploit/
	| /resolved symbol prepare_kernel_cred to/
	| /Ac1dB1tCh3z/
	| / sh-3.1#/
	| / sh-3.2#/
	| / sh-3.3#/
	| / sh-2.0#/
	| /LD_AUDIT/
	| /LD_AOUT_LIBRARY_PATH/
	| /LD_AOUT_PRELOAD/
	| /LD_DYNAMIC_WEAK/
	| /LD_ORIGIN_PATH/
	| /MODPROBE_OPTIONS.*staprun/
	| /getuid\.so.*xtxqtcmd/
	| /fucksheep/
	| /[Aa]ssertion .\!setuid\(0\). failed/
	| /[Aa]ssertion .\!close\(fd\). failed/
	|  /^-r.s.*root.*\/bin\/(sh|csh|tcsh)/
	| /Jumping to address/
	| /(shell|xploit)_code/
	| /(shell|xploit)code/
	| /execshell/
	| /BOT_VERSION/
	| /(cd \/; uname -a; pwd; id)/
	| /[aA][dD][oO][rR][eE]/	# rootkit
	| /setuid\(0\)/
	| /setgid\(0\)/
	| /execl\(\"\/bin\/sh\"\, \"\/bin\/sh\", NULL\)/
	| /open\(\"\/proc\/ksyms\", \"r\"\)/
	| /open\(\"\/dev\/(mem|kmem|oldmem|shmem)/
	| /execl\(\"\/proc\/self\/exe\"/
	| /selinux_ops|dummy_security_ops|capability_ops/
	| /[Xx][Hh][Ee3][Ll1][Ll1][Cc][Oo0[Dd][Ee]/;

redef SSHD_POLICY::suspicous_command_list =
	/^rpcinfo/
	| /uname -a/
	# it is quite handy that code writers tell us what they are doing ..
	| /[Ll][Ii][Nn][Uu][Xx][[:blank:]]*([Ll][Oo0][Cc][Aa][Ll]|[Kk][Ee][Rr][Nn][Aa][Ll]).*([Ee][Xx][Pp][Ll][Oo0][Ii][Tt]|[Pp][Rr][Ii][Vv][Ll][Ee][Gg][Ee])/
	# this general interface form has become really common.  Thanks!
	#| /(printf|print|fprintf|echo)[[:blank:]].*\[(\-|\+|\*|[Xx]|[:blank:]|!)[[:blank:]].*\]/
	# second half of above generalization.  Seriously, I really appreciate the standardization of interfaces!
	#| /[[:blank:]]*\[(\-|\+|\*|[Xx]|[:blank:]|!)[[:blank:]]*\]|[Aa][Bb][Uu][Ss][Ii][Nn][Gg]/
	| /[Aa][Bb][Uu][Ss][Ii][Nn][Gg]|[Pp][Tt][Rr][Aa][Cc][Ee]/
	#| /|[Ll][Aa][Uu][Nn][Cc][Hh][Ii][Mn][Gg]|[Ss][Yy][Mm][Bb][Oo][Ll]|[Pp][Rr][Ii]Vv]|[Tt][Rr][Ii][Gg][Gg][Ee][Rr]|[Tt][O0o][O0o][Ll]/
	# words words words, probably too noisy
	| /[Ss][Hh][Ee3][Ll1][Ll1][Cc][Oo0][Dd][Ee]|[Pp][A@][Yy][Ll1][Oo0][Aa@][Dd]|[Ee][Xx][Pp][Ll1][Oo0][Ii][Tt]/
	# words that I do not commonly find in scientific or benchmark code ...
	| /[Kk]3[Rr][Nn]3[Ll]|[Rr]3[Ll]3[Aa][Ss$]3|[Mm]3[Tt][Hh]34[Dd]|[Ll][Oo0][Oo0][Kk]1[Nn][Gg]|[Tt]4[Rr][Gg]3[Tt][Zz]|[Cc]0[Mm][Pp][Uu][Tt]3[Rr]|[Ss][Hh][Ee3][Ll1][Ll1][Cc][Oo0][Dd][Ee3]|[Bb][Ii1][Tt][Cc][Hh][Ee3][ZzSs$]/
	# bit of a catch all re the generic interface construct [+]/[-] ...
	#  first case when the IC is the first character set in the line
	#| /^.{0,8}\[[-\/|]\]/
	#  then we look for space *after* the [x] grouping
	| /^.{0,8}\[[-\/|+]\]/;


redef SSHD_POLICY::bad_key_list += {
	# keys from https://github.com/rapid7/ssh-badkeys
	# ssh-keygen -lf X.pub
	#
	# authorized
	"04:9b:f5:de:de:27:10:5a:b8:8d:ab:79:cd:17:e8:57", # array-networks-vapv-vxag.pub (DSA 1024)
	"27:c6:ad:f9:a6:4d:22:3f:18:b0:3b:df:81:1c:57:45", # ceragon-fibeair-cve-2015-0936. mateidu@localhost (RSA 1024)
	"f0:96:10:b7:d6:38:38:de:f4:b4:d2:df:5e:f8:2d:74", # loadbalancer.org-enterprise-va root@lbslave (DSA)
	"e4:4d:3e:11:db:3f:06:be:31:40:d8:fe:03:8e:46:8b", # quantum-dxi-v1000 (DSA 1024)
	"dd:3b:b8:2e:85:04:06:e9:ab:ff:a8:0a:c0:04:6e:d6", # vagrant insecure public key (RSA 2048)
	# host
	"49:53:bf:94:2a:d7:0c:3f:48:29:f7:5b:5d:de:89:b8", # tandberg-vcs, hgb@hgbpc (DSA 1024)
	};

