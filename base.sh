#!/bin/bash


export LANG=c;
test "$(whoami)" != 'root' && (echo you are using a non-privileged account; exit 1)
DATE=`date +%Y%m%d`

function Out_msg(){
	NUM=$1
	DESCRIPTION=$2
	
    echo "====================================="
    echo "==linux-安全要求-设备-通用-配置-$NUM===="
    echo "====================================="

    echo -e $DESCRIPTION
    echo "====================================="

}

function Out_msg_end(){
    echo "-----------------------"
    echo "--------CHECKED--------"
    echo 
}

function Chk_Conf_Backup(){
	SYS_CONF=$1;
if [ -f $SYS_CONF ]; then

	if [ -f $SYS_CONF"_"$DATE ]; then
		echo "$SYS_CONF was backuped today";
		return 1;
	else
		cp $SYS_CONF $SYS_CONF"_"$DATE;
		return 0;
	fi
else
    echo "[error ] "$SYS_CONF"no exist !"
fi
}
function BACKUP_SYS_CONF(){
	Chk_Conf_Backup /etc/passwd;	
    Chk_Conf_Backup /etc/securetty;
	Chk_Conf_Backup /etc/ssh/sshd_config;
	Chk_Conf_Backup /etc/login.defs

	return 0;
}

############################################################################################
############################################################################################
############################################################################################

#linux-安全要求-设备-通用-配置-1
function Check_Linux_1(){
    Out_msg 1 "修改用户主目录权限";

    #awk -F":" '$6!~/(\/var|\/usr|\/sbin|\/etc|\/dev|\/bin|^\/$)/{print $6}' /etc/passwd|uniq|xargs -i find {} -maxdepth 0 -printf "%m %p\n" 2>/dev/null
    awk -F":" '($3==0 || $3>=500 ) && $6!~/(\/var|\/usr|\/sbin|\/etc|\/dev|\/bin|^\/$)/{print $6}' /etc/passwd|uniq|xargs -i find {} -maxdepth 0 -printf "echo \"chmod %m %p\";chmod %m %p\n" 2>/dev/null |bash 
    
    Out_msg_end;
    return 0;
}


#linux-安全要求-设备-通用-配置-2
function Check_Linux_2(){

    Out_msg 2 "删除或锁定与设备运行、维护等工作无关的账号。"
    
    NOLOGIN_USER="deamon bin sys adm uucp nuucp printq guest nobody lpd sshd";
    for i in $NOLOGIN_USER; 
    do  
        echo "check username: "$i;
        awk -F: '{if ( $1=="'$i'" && $7!~/\/sbin\/nologin|\/bin\/sync|\/sbin\/shutdown|\/sbin\/halt|\/bin\/false/  ){print "usermod -s /sbin/nologin "$1}}' /etc/passwd|bash 
    done

    Out_msg_end;
    return 0;
	
}

function Check_Linux_3(){

    Out_msg 3 "限制具备超级管理员权限的用户远程登录";


    echo "检查是否限制root用户远程telnet登录："；
    Var=`grep -i "^CONSOLE=/dev/tty01$" /etc/securetty`
    if [ -n "$Var" ] 
     then
        echo "已限制";
    else
        echo "未限制，正在修复:";
		echo "CONSOLE=/dev/tty01" >> /etc/securetty;
		Var_telnet=`grep "disable" /etc/xinetd.d/telnet |awk -F"=" '{print $2}'`

		if [ $Var_telnet == "no" ]
		then
		/etc/init.d/xinetd restart
		fi
		echo "完成";
    fi

    echo "检查是否限制root用户直接远程ssh登录:"
    Var=`grep -i "^PermitRootLogin.*\ no" /etc/ssh/sshd_config`
     if [ -n "$Var" ] 
     then
       echo "已限制ssh";
    else
        echo "未限制ssh";
		echo "PermitRootLogin no" >> /etc/ssh/sshd_config;
		/etc/init.d/sshd restart ;
    fi

    Out_msg_end;
    return 0;
}
function Check_Linux_4(){

    Out_msg 4 "根据系统要求及用户的业务需求，建立多帐户组，将用户账号分配到相应的帐户组。"
	#do not something;
    echo "请手动检查"
    Out_msg_end;
	return 0;
}

function Check_Linux_5(){
    Out_msg 5 "对系统账号进行登录限制，确保系统账号仅被守护进程和服务使用，不应直接由该账号登录系统。如果系统没有应用这些守护进程或服务，应删除这些账号。"
	#do not something;
    echo "请手动检查";
    Out_msg_end;
	return 0;
}


function Check_Linux_6(){

    Out_msg 6 "对于采用静态口令认证技术的设备，口令长度至少8位，并包括数字、小写字母、大写字母和特殊符号4类中至少3类。"
	
	Chk_Conf_Backup /etc/login.defs;
    Chk_Conf_Backup /etc/pam.d/system-auth; 

    Var=`awk '$0~/^PASS_MIN_LEN/{print $2}'  /etc/login.defs`
	
    if [ $Var -ge 8 ] 
    then
       echo "已限制用户密码长度";
    else
        echo "未限制用户密码长度";
		sed -i "s/^PASS_MIN_LEN\ *.*$/#&/" /etc/login.defs
		echo "PASS_MIN_LEN	8" >>/etc/login.defs
    fi

	Var=`awk '$1~/^password/&&$2~/requisite/&&$0~/difok=1/&&$0~/lcredit=1/&&$0~/ucredit=1/&&$0~/credit=1/{print $0}' /etc/pam.d/system-auth`
	if [ -z "$Var" ]
	then
			echo "未限制用户密码强度";
		
			sed -i 's/password.*requisite.*$/#&\npassword    requisite     pam_cracklib.so retry=6 difok=1 lcredit=1 ucredit=1 credit=1/g' /etc/pam.d/system-auth
	else
			echo "已限制用户密码强度";
	fi
	Out_msg_end;

}
function Check_Linux_7(){

	    Out_msg 7 "对于采用静态口令认证技术的设备，帐户口令的生存期不长于90天。"

			    Chk_Conf_Backup /etc/login.defs;
	
		Var=`awk '$0~/^PASS_MAX_DAYS/{print $2}'  /tmp/login.defs`

		if [ "$Var" == "90" ]
			then
				echo -e "已限制帐号密码限期为90天\n不作修改";
        	else
			    echo -e "未限制帐号密码限期为90天\n现在进行修改......";
                sed  -i "s/^PASS_MAX_DAYS\ *.*$/#&\nPASS_MAX_DAYS 90/" /tmp/login.defs
		fi
		
		Out_msg_end;

}

function Check_Linux_8(){
		Out_msg 8 "对于采用静态口令认证技术的设备，应配置当用户连续认证失败次数超过6次（不含6次），锁定该用户使用的账号。"
		CONF_FILE=/etc/pam.d/system-auth
		Chk_Conf_Backup $CONF_FILE 
		Var=`awk '$1~/^password/&&$2~/requisite/&&$0~/retry=6/{print $0}' $CONF_FILE`
		
		if [ -z "$Var" ]
			then
				echo "未限制用户密码强度";
		        sed  's/password.*requisite.*$/#&\npassword    requisite     pam_cracklib.so retry=6 difok=1 lcredit=1 ucredit=1 credit=1/g' $CONF_FILE 
	    else
	            echo "已限制用户密码强度";
	    fi

		Out_msg_end;

}

function Check_Linux_9(){
	Out_msg 9 "在设备权限配置能力内，根据用户的业务需要，配置其所需的最小权限。"

	echo "do nothing"

	Out_msg_end;

}

function Check_Linux_10(){
	Out_msg 10 "控制用户缺省访问权限，当在创建新文件或目录时 应屏蔽掉新文件或目录不应有的访问允许权限。\n防止同属于该组的其它用户及别的组的用户修改该用户的文件或更高限制";
	CONF_FILE=/etc/profile
	Chk_Conf_Backup $CONF_FILE;
	Var=`awk '$1~/umask/' $CONF_FILE`
	
	if [ -z "$Var" ]
		then
			echo -e "未设置用户UMASK值\n现在设置......";
			echo "umask 027" >> $CONF_FILE;
	else
			echo "已设置用户UMASK值";

	fi

	Out_msg_end;
}

function Check_Linux_11(){
	    Out_msg 11 "控制FTP进程缺省访问权限\n当通过FTP服务创建新文件或目录时应屏蔽掉新文件或目录不应有的访问允许权限。";

 
        if [ -f /etc/ftpusers ] ; then
            FTPUSERS_FILE=/etc/ftpusers
            FTPACCESS_FILE=/etc/ftpaccess
        else
            if [-d /etc/ftpd] ; then
            FTPUSERS_FILE=/etc/ftpd/ftpusers
            FTPACCESS_FILE=/etc/ftpd/ftpaccess
            else
                "/etc/ftpusers和/etc/ftpd/ftpusers不存在，请检查是否已安装ftp"
                return 0;
            fi
        fi
        Chk_Conf_Backup $FTPUSERS_FILE 
        Chk_Conf_Backup $FTPACCESS_FILE
        echo "restricted-uid *" > $FTPACCESS_FILE;
        echo -e "chmod      no guest,anonymous\ndelete      no guest,anonymous\noverwrite   no guest,anonymous\nrename     no guest,anonymous\numask      no anonymous" >> $FTPACCESS_FILE;
        echo "root
daemon
bin
sys
adm
lp
uucp
nuucp
listen
nobody
noaccess
nobody4" >> $FTPUSERS_FILE 
         
		    Out_msg_end;
}

function Check_Linux_12(){
	    Out_msg 12 "设备应配置日志功能，对用户登录进行记录，记录内容包括至少包括审计日期、时间、发起者信息、审计类型、审计内容描述和结果等要素。";
        SYSLOG_PACKAGE=`ps -ef|grep syslog |grep -v grep |awk '{print $8}'|xargs which|xargs rpm -qf|head -1`

        if [ -z $SYSLOG_PACKAGE ];
        then

            echo " 未找到syslog进程! 检查是否已启动syslog(或rsyslog)";
            echo "请尝试使用service syslog start并设置开机启动chkconfig syslog on"
            echo "或service rsyslog restart和chkconfig rsyslog on"
            return 1;
        else
             SYSLOG_CONF_FILE=`rpm -ql $SYSLOG_PACKAGE|grep '.*conf$'|head -1`
            Chk_Conf_Backup $SYSLOG_CONF_FILE
        fi

        echo -e "auth.info\t\t/var/adm/authlog\n*.info;auth.none\t\t/var/adm/syslog\n" >> $SYSLOG_CONF_FILE
        if [ -d /var/adm/ ]; 
            then 
#do nothing;
                echo ;
        else 
            mkdir /var/adm;
            chown root:sys /var/adm
        fi
        touch /var/adm/authlog /var/adm/syslog
        chown root:sys /var/adm/authlog
        chown root:sys /var/adm/syslog
        chmod 600 /var/adm/authlog  
        chmod 640 /var/adm/syslog
        SYSLOG_EXECUTEFILE=`rpm -ql $SYSLOG_PACKAGE |grep '^/etc/rc.d/init.d/*\|^/etc/init.d/*'|head -1`
        $SYSLOG_EXECUTEFILE restart;
		Out_msg_end;
}

function Check_Linux_13(){
	    Out_msg 13 "设备应配置日志功能，记录对与设备相关的安全事件。";
        SYSLOG_PACKAGE=`ps -ef|grep syslog |grep -v grep |awk '{print $8}'|xargs which|xargs rpm -qf|head -1`

        if [ -z $SYSLOG_PACKAGE ];
        then
            echo " 未找到syslog进程! 检查是否已启动syslog(或rsyslog)";
            echo "请尝试使用service syslog start并设置开机启动chkconfig syslog on"
            echo "或service rsyslog restart和chkconfig rsyslog on"
            return 1;
        else 
             SYSLOG_CONF_FILE=`rpm -ql $SYSLOG_PACKAGE|grep '.*conf$'|head -1`
            Chk_Conf_Backup $SYSLOG_CONF_FILE
        fi

        echo -e "*.err;kern.debug;daemon.notice;\t\t/var/adm/messages" >> $SYSLOG_CONF_FILE;

        if [ -d /var/adm/ ]; 
            then 
#do nothing;
            echo ;
            echo ;
        else 
            mkdir /var/adm;
            chown root:sys /var/adm
        fi

        SYSLOG_EXECUTEFILE=`rpm -ql $SYSLOG_PACKAGE |grep '^/etc/rc.d/init.d/*\|^/etc/init.d/*'|head -1`
        $SYSLOG_EXECUTEFILE restart;

		    Out_msg_end;
}

function Check_Linux_14(){
	    Out_msg 14 "[可选]设备配置远程日志功能，将需要重点关注的日志内容传输到日志服务器。";
        echo "请手动修改/etc/syslog.conf（或rsyslog.conf）："
        echo -e "加上以下几行：\nauth.info\t\t@loghost  \n*.info;auth.none\t\t@loghost  \n*.emerg\t\t@loghost  \nlocal7.*\t\t@loghost"
        echo "其中loghost为日志服务器ip；"
		    Out_msg_end;
}

function Check_Linux_15(){
	    Out_msg 15 "对于使用IP协议进行远程维护的设备，设备应配置使用SSH等加密协议，并安全配置SSHD的设置。";

        service sshd restart;
            
		    Out_msg_end;
}

function Check_Linux_16(){
	    Out_msg 16 "设备应支持列出对外开放的IP服务端口和设备内部进程的对应表。";
        echo -e "请手动检查：\n1,开放的服务列表,命令:  # chkconfig --list\n2,开放的端口列表,命令:  # netstat -an\n3,服务端口和进程对应表,命令：#cat  /etc/services"
		    Out_msg_end;
}

function Check_Linux_17(){
	    Out_msg 17 "对于通过IP协议进行远程维护的设备，设备应支持对允许登陆到该设备的IP地址范围进行设定。";

        echo -e "请手动检查：\n1,允许访问的IP列表：#cat /etc/hosts.allow\n2,禁止访问的IP列表：#cat /etc/hosts.deny"
		    Out_msg_end;
}

function Check_Linux_18(){
        Out_msg 18 "主机系统应该禁止ICMP重定向，采用静态路由"
        
        Var=`sysctl -a|awk '$1~/net.ipv4.conf.all.accept_redirects/{print $3}'`
        
        if [ "$Var" != "0" ] ; then
            echo -e "未禁止ICMP重定向;\n现在修改......" 
            Chk_Conf_Backup /etc/sysctl.conf
            echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
            sysctl -p;
        else
            echo "已禁止ICMP重定向"
        fi


        Out_msg_end;
}

function Check_Linux_19(){
    Out_msg 19 "对于不做路由功能的系统，应该关闭数据包转发功能。"
    Var=`sysctl -a|awk '$1~/net.ipv4.ip_forward/{print $3}'`
        
        if [ "$Var" != "0" ] ; then
            echo -e "未关闭数据包转发功能" 
            Chk_Conf_Backup /etc/sysctl.conf
            echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
            sysctl -p;
        else
            echo "已关闭数据包转发功能"
        fi
 
    Out_msg_end;
}

function Check_Linux_20(){
    Out_msg 20 "对于具备字符交互界面的设备，应配置定时帐户自动登出";
    
    Chk_Conf_Backup /etc/profile
    Chk_Conf_Backup  /etc/environment
    Chk_Conf_Backup /etc/security/.profile
    Var=`env |awk -F"=" '$1~/TIME/{print $2}'` 
            if  [ "$Var" -ge 120 ] && [ "$Var" != "0"]; then
                echo "已加固"
            else
                Var2=`grep "^TMOUT=120" /etc/profile|head -1 |awk -F"=" '{print $1}'`
                    
                    if [ -z $Var2 ] ; then
                        echo "未加固，现在修改/etc/profile，etc/environment，/etc/security/.profile文件";            
                echo "TMOUT=120 ; TIMEOUT=120 ; export readonly TMOUT TIMEOUT" >> /etc/profile;
                echo "TMOUT=120 ; TIMEOUT=120 ; export readonly TMOUT TIMEOUT" >> /etc/environment;
                echo "TMOUT=120 ; TIMEOUT=120 ; export readonly TMOUT TIMEOUT" >> /etc/security/.profile;

                    else
                        echo "已加固"
                            fi
                            fi
    Out_msg_end;
    return 0;
}
function Check_Linux_21(){
    Out_msg 21 "对于具备图形界面（含WEB界面）的设备，应配置定时自动屏幕锁定。"
    
        Chk_Conf_Backup /etc/profile
    Var=`awk '$1~/^setterm/{print $3}' /etc/profile`;
        
    if [ "$Var" == "1" ] ; then
        echo "已加固；"
    else
        echo "未加固，现在修改/etc/profile文件";
        echo "setterm -blank 1" >> /etc/profile;
    fi
        
    Out_msg_end;
    return 0;
}

function Check_Linux_22(){
    Out_msg 22 "涉及账号、账号组、口令、服务等的重要文件和目录的权限设置不能被任意人员删除，修改。"
    
Var=` find /etc/rc.d/init.d/ -maxdepth 1 -mindepth 1 ! -user root  |head -1`
if [ -z $Var ] ;
then
	echo "/etc/rc.d/init.d/下所有文件属主均为root。不需修改。"
else
	for i in `find /etc/rc.d/init.d/ -maxdepth 1 -mindepth 1 ! -user root`; 
	do 
	echo -e "检查文件："$i
	echo -e "文件属主不是root\t现在修改...";
	chown root $i;
	echo "已修改"
	done
fi


Var=`find /etc/rc.d/init.d/ -maxdepth 1 -mindepth 1 ! -perm 750 -o ! -user root  |head -1`; 
if [ -z $Var ] ;
then
	echo "/etc/rc.d/init.d/下所有文件权限为750"
else 
	for i in `find /etc/rc.d/init.d/ -maxdepth 1 -mindepth 1 ! -perm 750`; 
	do 
	echo -e "检查文件："$i
	echo -e "文件权限不是750\t现在修改..."
	chmod 750 $i ；
	echo -e "已修改为750。";
	done
fi

    Out_msg_end;
}

function Check_Linux_23(){
    Out_msg 23 "应该从应用层面进行必要的安全访问控制，比如FTP服务器应该限制ftp可以使用的目录范围。"

    echo "do nothing!"
    #do nothings    

    Out_msg_end;
    return 0
}

function Check_Linux_24(){
    Out_msg 24 "在系统安装时建议只安装基本的OS部份，其余的软件包则以必要为原则，非必需的包就不装。"

echo -e "执行下列命令，查看版本及大补丁号。\n#uname –a\n执行下列命令，查看各包的补丁号\n#rpm -qa\n" 

    Out_msg_end
    return 0;
}

function Check_Linux_25(){
    Out_msg 25 "应根据需要及时进行补丁装载。对服务器系统应先进行兼容性测试。"
echo -e "#rpm –qa命令查看版本；\n#RPM-ivh ***.RPM 命令给系统打补丁；"

    Out_msg_end;
    return 0;
}

function Check_Linux_26(){
    Out_msg 26 "如果网络中存在信任的NTP服务器，应该配置系统使用NTP服务保持时间同步。"

        echo -e "手动配置，参考配置操作：\n
#crontab -e 
加入一行：30 8 * * * root /usr/sbin/ntpdate $ServerIP; /sbin/hwclock -w 
（$ServerIP为NTP服务器IP地址,i.e:192.168.0.1）
并检查crond是否已启用：#chkconfig --list|grep crond；service crond status；
需要将其开启：#chkconfig crond on; service crond start;
检查ntpd服务器是否已关闭，#chkconfig --list|grep ntpd；service ntpd status;
需要将其关闭：#chkconfig ntpd off;service ntpd stop"

    Out_msg_end;
    return 0;
}

function Check_Linux_27(){
    Out_msg 27 "NFS服务：如果没有必要，需要停止NFS服务；如果需要NFS服务，需要限制能够访问NFS服务的IP范围。"
    echo -e "
停止NFS服务
Service nfs stop

限制能够访问NFS服务的IP范围：
编辑文件：vi /etc/hosts.allow
增加一行: nfs: 允许访问的IP    
    "

    Out_msg_end;
    return 0;
}

function Check_Linux_28(){
    Out_msg 28 "防止堆栈缓冲溢出";

        Limit_Conf_File=/etc/security/limits.conf
        Var=`ulimit -c`
            if [ $Var == 0 ] ; then
                echo "已加固"；
            else
                echo "未配置$Limit_Conf_File的core项为0；现在修改..."
                echo "* soft core 0" >>$Limit_Conf_File
                echo "* hard core 0" >>$Limit_Conf_File
                echo "已修改。"
            fi

    Out_msg_end;
    return 0;
}

function Check_Linux_29(){
    Out_msg 29 "列出系统启动时自动加载的进程和服务列表，不在此列表的需关闭。";

    echo "关闭不经常使用的服务:如sendmail portmap cups named apache xfs vsftpd lpd linuxconf identd smb等服务。"
    echo "请手动执行ServConf.sh脚本。"
    
    Out_msg_end;
    return 0;
}

function Check_Linux_30(){
    Out_msg 30 "监视服务器的CPU、硬盘、内存、网络等资源。";

    echo "使用第三方主机监控系统进行监控"    

    Out_msg_end;
    return 0;
}

function Check_Linux_31(){
    Out_msg 31 "列出所需要服务的列表(包括所需的系统服务)，不在此列表的服务需关闭。"

echo "根据系统应用情况选择禁止下列不必要的基本网络服务。
time echo discard daytime chargen fs dtspc exec comsat talk finger uucp name xaudio netstat ufsd rexd systat sun-dr uuidgen krb5_prop"
    Out_msg_end;
    return 0;
}
#===========================================================




#==================main start================================



BACKUP_SYS_CONF;

for i in `seq 1 31`
do
    Check_Linux_$i;
done

. ./Venus.sh 

for i in `awk -F"[ (_]" '/function\ Venus/{print $4}' ./Venus.sh `
do

if [ $i -ne 38 ] && [ $i -ne 54 ]  ; then
    Venus_Linux_$i;
else
    echo "Venus_Linux_$i项有风险较大，不修改"
fi
        
done


echo "完成初始化。请重启操作系统reboot"

exit 0;
