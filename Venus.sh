#/bin/bash
function Out_msg_Venus(){
	NUM=$1
	DESCRIPTION=$2
	
    echo "====================================="
    echo "==========Venus-Linux-$NUM==========="
    echo "====================================="

    echo -e $DESCRIPTION
    echo "====================================="


}



#=========================启明星辰==========================
function Venus_Linux_1(){
    Out_msg_Venus 1 "去除不需要的帐号、修改默认帐号的shell变量"

    Chk_Conf_Backup /etc/passwd
    DEL_USER="lp sync shutdown halt  operator games gopher"
    for i in  $DEL_USER
    do
	    if [ `grep -E "^\<$i\>" /etc/passwd|wc -l ` -ne 0 ]
	    then
		    echo "用户$i存在，现在删除。"
		    /usr/sbin/userdel $i;
		    echo "用户$i已删除";
	    else
		    echo "用户$i已删除,无需修改。"
	    fi
    done

    NOLOGIN_USER="news uucp ftp";
    for i in $NOLOGIN_USER; 
    do  
        echo "check username: "$i;
        awk -F: '{if ( $1=="'$i'" && $7!~/\/sbin\/nologin|\/bin\/sync|\/sbin\/shutdown|\/sbin\/halt|\/bin\/false/  ){print "echo \"现在修改用户"'$i'"的登陆域\";usermod -s /sbin/nologin "$1}}' /etc/passwd|bash 
    done  

    echo "已加固"
    Out_msg_end;
    return 0;
}

function Venus_Linux_2 (){
    Out_msg_Venus 2 "passwd文件检查"

    Chk_Conf_Backup /etc/passwd
    Chk_Conf_Backup /etc/shadow
    CHECK_SHADOW_NUM=`awk -F: '{if($2 != "x" && $2 != "*") print $1}' /etc/passwd|wc -l `
    CHECK_PASSWD_NUM=`wc -l /etc/passwd|awk '{print $1}'`

if [ $CHECK_SHADOW_NUM -ne $CHECK_PASSWD_NUM ] ; then

    NOSHADOW_USER=`awk -F: '{if($2 != "x" && $2 != "*") print $1}' /etc/passwd`
    if [ -n $NOSHADOW_USER ] 
    then
        for i in $NOSHADOW_USER; do
            echo "$i用户异常，将删除后重建，密码设置为与“"$i"_2012”格式。"
                 /usr/sbin/userdel $i
                 /usr/sbin/useradd $i
                 echo $i"_2012"| /usr/bin/passwd $i --stdin
            done
    else
        echo "已加固"
    fi
 else
        echo -e "[error] /etc/passwd文件检查出错，跳过自动检查\n请手动检查系统是否启用shadow密码"
        return 1;
fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_3(){
    Out_msg_Venus 3 "shadow文件检查";

    Chk_Conf_Backup /etc/passwd
    Chk_Conf_Backup /etc/shadow
    lines=`sed '/^nfsnobody/'d /etc/passwd`
    check_users=`echo "$lines" | awk -F: '{if($3 == 0 || $3 >= 500) print $1}'`
    no_pwd_users=`awk -F: '{if($2=="!!") print $1}' /etc/shadow`
    for user in $check_users
        do
        for loop in $no_pwd_users
            do
            if [ "$loop" = "$user" ]; then
                echo "$user未设置密码，现在修改密码为“"$user"_2012”"
	            echo $user"_2012" |/usr/bin/passwd --stdin  $user 
            fi
        done
    done
    
    echo "已加固"

    Out_msg_end;
    return 0;
}

function Venus_Linux_4(){
    Out_msg_Venus 4 "root帐号shell变量信息检查";
    Chk_Conf_Backup /etc/passwd
        SHELL_PATH=$(which bash) ; 
        PASSWD_ROOT_PATH=`awk -F ":" '$1~/^root$/{print $7}' /etc/passwd`
        if [ "$SHELL_PATH" != "$PASSWD_ROOT_PATH" ] ; then
            echo "root帐号shell为"$PASSWD_ROOT_PATH;
            echo "现在修改为$SHELL_PATH";
            /usr/sbin/usermod -s $SHELL_PATH root
        else
            echo "已加固";
                fi
    Out_msg_end;
    return 0;
}

function Venus_Linux_5(){
    Out_msg_Venus 5 "禁用不需要的账号";
    Chk_Conf_Backup /etc/passwd;
    Chk_Conf_Backup /etc/shadow;

    echo "do nothing!"
    echo "Venus_Linux_1项已加固"
        
    Out_msg_end;
    return 0;
}
function Venus_Linux_9(){
    Out_msg_Venus 9 "系统uid=0帐号信息检查";
    Chk_Conf_Backup /etc/passwd
        if [ `awk -F: '{if($3==0&&$1!="root") print $1}' /etc/passwd|wc -l`  -ne 0 ] ;then
            echo "存在UID为0（非root）的用户，将删除用户"
            WARN_USER=`awk -F: '{if($3==0&&$1!="root") print $1}' /etc/passwd`
            
            for i in $WARN_USER; do
                    echo $i"用户UID为0，删除此用户"
                    /usr/sbin/userdel $i;
                done
        else
            echo "已加固"
        fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_10(){
    Out_msg_Venus 10 "使root PATH环境变量中不包含当前目录";
    Chk_Conf_Backup /etc/profile
    if [ -z "`env |awk -F "=" '$1~/^PATH$/{print $2}'|awk -F ":" '{for ( i=1;i<=NF;i++) if($i=="."){print $i}}'`" ];then
        echo "root用户环境变量中包含当前目录，检查/etc/profile文件:"
        
            if [ -z `cat /etc/profile|awk -F "=" '$1~/^PATH$/{print $2}'|awk -F ":" '{for ( i=1;i<=NF;i++) if($i=="."){print $i}}'`]  ; then
                echo "现在修改/etc/profile文件"
                sed -i '/[ ^]PATH=/s/\.://g' /etc/profile
                echo "已加固，需重新登陆才能生效"
            else
                echo "/etc/profile正确，已加固，请重新登陆再检查"
                    fi
    else
        echo "已加固"
    fi
        
    Out_msg_end;
    return 0;
}
function Venus_Linux_11(){
    Out_msg_Venus 11 "对root为ls、rm设置别名";

    ROOT_SHELL_FILE=~/.`basename $SHELL`rc

    Var=`grep "alias ls=" $ROOT_SHELL_FILE|head -1`
    if [ -n "$Var" ] ; then
        echo "已加固"
    else
        echo "未添加ls命令别名,现在修改"
        echo "alias ls='ls -aol --color=tty'" >> $ROOT_SHELL_FILE
        alias ls='ls -aol --color=tty'
            fi
    Var=`grep "alias rm=" $ROOT_SHELL_FILE|head -1`
    if [ -n "$Var" ] ; then
        echo "已加固"
    else
        echo "未添加rm命令别名,现在修改"
            echo "alias rm='rm -i'" >> $ROOT_SHELL_FILE
            alias rm='rm -i'
            fi
    Out_msg_end;
    return 0;
}
function Venus_Linux_12(){
    Out_msg_Venus 12 "缺省密码长度限制";
    Chk_Conf_Backup /etc/login.defs
Var=`awk '$0~/^PASS_MIN_LEN/{print $2}'  /etc/login.defs`
	
    if [ $Var -ge 8 ] 
    then
       echo "已限制用户密码长度";
    else
        echo "未限制用户密码长度";
		sed -i "s/^PASS_MIN_LEN\ *.*$/#&/" /etc/login.defs
		echo "PASS_MIN_LEN	8" >>/etc/login.defs
    fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_13(){
    Out_msg_Venus 13 "密码最大有效天数";
    Chk_Conf_Backup /etc/login.defs

		Var=`awk '$0~/^PASS_MAX_DAYS/{print $2}'  /etc/login.defs`

		if [ "$Var" == "90" ]
			then
				echo -e "已限制帐号密码限期为90天\n不作修改";
        	else
			    echo -e "未限制帐号密码限期为90天\n现在进行修改......";
                sed  -i "s/^PASS_MAX_DAYS\ *.*$/#&\nPASS_MAX_DAYS 90/" /etc/login.defs
		fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_14(){
    Out_msg_Venus 14 "密码最小有效天数";
    Chk_Conf_Backup /etc/login.defs
		Var=`awk '$0~/^PASS_MIN_DAYS/{print $2}'  /etc/login.defs`

		if [ "$Var" == "10" ]
			then
				echo -e "已限制帐号密码最小限期为10天\n不作修改";
        	else
			    echo -e "未限制帐号密码最小限期为10天\n现在进行修改......";
                sed  -i "s/^PASS_MIN_DAYS\ *.*$/#&\nPASS_MIN_DAYS 10/" /etc/login.defs
		fi


    Out_msg_end;
    return 0;
}
function Venus_Linux_15(){
    Out_msg_Venus 15 "密码过期提前警告天数";
    Chk_Conf_Backup /etc/login.defs

	Var=`awk '$0~/^PASS_WARN_AGE/{print $2}'  /etc/login.defs`

		if [ "$Var" == "5" ]
			then
				echo -e "已修改密码过期提前警告天数为5天\n不作修改";
        	else
			    echo -e "未修改密码过期提前警告天数为5天\n现在进行修改......";
                sed  -i "s/^PASS_WARN_AGE\ *.*$/#&\nPASS_WARN_AGE 5/" /etc/login.defs
		fi


    Out_msg_end;
    return 0;
}
function Venus_Linux_16(){
    Out_msg_Venus 16 "超时自动注销登录";

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
function Venus_Linux_19(){
    Out_msg_Venus 19 "使用pasword shadowing";
    Chk_Conf_Backup /etc/passwd
    Chk_Conf_Backup /etc/shadow
    
    if [ -f /etc/shadow ] ; then
        echo "已加固"
    else
        echo "现在加固"
        /usr/sbin/pwconv
            fi
    Out_msg_end;
    return 0;
}
function Venus_Linux_20(){
    Out_msg_Venus 20 "保证bash shell保存少量的（或不保存）命令";
    Chk_Conf_Backup /etc/profile
    
    HFS=`grep "HISTFILESIZE=30" /etc/profile`
    HS=`grep "HISTSIZE=30" /etc/profile`
        if [ -n "$HFS" ] && [ -n "$HS" ] ; then
            echo "已加固";
        else
            echo "未加固，现在修改/etc/profile文件"
            echo -e "HISTFILESIZE=30\nHISTSIZE=30" >> /etc/profile
                fi


    Out_msg_end;
    return 0;
}
function Venus_Linux_21(){
    Out_msg_Venus 21 "使用PAM禁止任何人su为root";
    echo "[warnning！]此加固项存在较大风险，如需修改请参考以下方法，手动配置："
    echo "1,将允许su到root的用户添加到wheel组(i.e将test用户添加到wheel组):#usermod -G wheel test"
    echo "2,备份/etc/pam.d/su文件"
    echo "3,将/etc/pam.d/su文件中#auth           required        pam_wheel.so use_uid行的注释符“#”删除"
    echo "4,使用其它用户su，验证配置是否成功"
    Out_msg_end;
    return 0;
}
function Venus_Linux_22(){
    Out_msg_Venus 22 "禁止使用ftp的帐号检查";
    Chk_Conf_Backup /etc/vsftpd/ftpusers
    Chk_Conf_Backup /etc/vsftpd.ftpusers

    if [ -f /etc/vsftpd.ftpusers ] ; then
        Var=`cat /etc/vsftpd.ftpusers|wc -l` 
        if [ $Var -ne 0 ] ; then
            echo "已加固"
        fi
    else
        echo "未加固，现在修改。"
        if [ -f /etc/vsftpd/ftpusers ] ; then
            cp /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers
        else
            echo "root" >> /etc/vsftpd.ftpusers
        fi
    fi
    Out_msg_end;
    return 0;
}
function Venus_Linux_32(){
    Out_msg_Venus 32 "xinetd/inetd服务信息检查";

    INET=`rpm -qa | grep xinetd`
    INET_NAME=`echo $INET|awk -F"-" '{print $1}'`
    if [ -z $INET ] ;then
        echo "未安装xinetd或inetd。请先安装xinetd或inetd组件!"；
        return 1;
    fi
    INET_SCRIPT=`rpm -ql $INET |grep "^/etc/rc.*inetd"`
    $INET_SCRIPT status;
    RETVAL=$?
    if [ $RETVAL -ne 0 ] ;then
        echo "$INET_NAME未启动";
        echo "现在启动$INET_NAME"
        $INET_SCRIPT start ;
        /sbin/chkconfig $INET_NAME on
    else
        echo "$INET_NAME已启动，已加固"
    fi
    
    Out_msg_end;
    return 0;
}
function Venus_Linux_33(){
    Out_msg_Venus 33 "/etc/host.conf信息检查";

    CONF_FILE=/etc/host.conf
    Chk_Conf_Backup $CONF_FILE;
    Var=`grep "order hosts,bind" $CONF_FILE |wc -l`
    
        if [ $Var -ne 0 ] ; then
            echo "已加固"
        else
            echo "未加固，现在修改$CONF_FILE文件"
            echo "order hosts,bind">> $CONF_FILE;
                fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_36(){
    Out_msg_Venus 36 "不同主机间信任关系检查";
    CONF_FILE=/etc/hosts.equiv

    if [ -f $CONF_FILE ] ;then
        echo "未加固,现在删除$CONF_FILE文件";
    	Chk_Conf_Backup $CONF_FILE; 
        rm -f $CONF_FILE;
    else
        echo "已加固"
    fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_38(){
    Out_msg_Venus 38 "系统ping响应信息检查";
    Var=`cat /proc/sys/net/ipv4/icmp_echo_ignore_all`
    
        if [ $Var -ne 0 ] ; then
            echo "已加固"
        else
            echo "未加固，现在加固"
            echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
            /sbin/sysctl -p
                fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_40(){
    Out_msg_Venus 40 "系统是否安装ftp信息检查";

    Var=` rpm -qa | grep ftp|wc -l` 
    Var2=`ls /etc/xinetd.d/*ftp*|wc -l`
    
    if [ $Var -gt 0 ] && [ $Var2 -gt 0 ] ; then
       echo "已加固"
    else
       echo "未加固,请手动安装ftp软件"
    fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_48(){
    Out_msg_Venus 48 "ftpd服务";

    Chk_Conf_Backup /etc/syslog.conf;
    if [ -f /etc/rc.d/init.d/xinetd ] ; then
        test 
    else
        echo "xinetd启动文件不存在，请检查xinetd是否正确安装"
        return 1;
    fi
    
    Var=`grep -v "#" /etc/xinetd.d/* | grep "service ftp"|wc -l` 
    if [ $Var -ne 0 ] ; then
       LOOP=`grep -v "#" /etc/xinetd.d/* | grep "service ftp" |awk -F":" '{print $1}'`
       
       for FTP_FILE_CONF in $LOOP; do
            VAR_FF=`awk '/^[^#].*server_args/&&/-l/&&/-r/&&/-A/&&/-S/' $FTP_FILE_CONF|wc -l`
            if [ $VAR_FF -ne 0 ] ; then
                echo "$FTP_FILE_CONF已加固"
            else
                echo "$FTP_FILE_CONF未加固,现在修改"
		sed -i 's/server_args.*/server_args\t= -l -r -A -S/' $FTP_FILE_CONF
		#sed -i ':a;N;$!ba;s/(.*\n)(.*})/\1server_args = -l -r -A -S\n\2/' $FTP_FILE_CONF;
            fi
       done
    else
        echo "未找到ftp相关配置文件，请手动检查/etc/xinetd.d/下是否存在ftp配置文件"
        return 1;
    fi

    Var=`grep "^ftp" /etc/syslog.conf|wc -l`
    
    if [ -n $var ] ; then
        echo "/etc/syslog.conf已加固"
    else
        echo "/etc/syslog.conf未加固，现在加固"
        echo "ftp.*  /var/log/ftpd" >>/etc/syslog.conf
    fi

        
    Out_msg_end;
    return 0;
}
function Venus_Linux_49(){
    Out_msg_Venus 49 "fingerd服务";
    
    if [ -f /etc/xinetd.d/finger ] ; then
        # /etc/xinetd.d/finger exist; 
        Var=`grep disable /etc/xinetd.d/auth |awk -F"=" '{print $2}'|sed 's/^[[:space:]]*//'`
        if [ $Var = "yes" ]; then
            echo "已加固"
        else
            echo "未加固，现在修改"
            sed 's/^.*disable.*=.*no.*/\tdisable\t\t= yes/g' /etc/xinetd.d/finger
        fi
    else
        # /etc/xinetd.d/finger not exist;
        echo "[warn]/etc/xinetd.d/finger not exist,无法加固"
    fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_52(){
    Out_msg_Venus 52 "更改主机解析地址的顺序";
    
    CONF_FILE=/etc/host.conf

    Chk_Conf_Backup $CONF_FILE;

    Var=`awk '$0~/order.*hosts.*bind.*/' $CONF_FILE|wc -l `

        if [ -n $var ] ; then
            echo "已加固"
        else
            echo "未加固,现在修改"
            echo "order hosts，bind" >>$CONF_FILE;
            echo "multi on" >>$CONF_FILE
            echo "nospoof on" >>$CONF_FILE
                fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_53(){
    Out_msg_Venus 53 "打开syncookie缓解syn flood攻击";

    CONF_FILE=/etc/sysctl.conf
    Chk_Conf_Backup $CONF_FILE
    Var=`cat /proc/sys/net/ipv4/tcp_syncookies`
    
    if [ $Var -ne 1 ] ; then
        echo "未加固，现在修改"
        echo "net.ipv4.tcp_syncookies = 1">>$CONF_FILE
        /sbin/sysctl -p
    else
        echo "已加固";
            fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_54(){
    Out_msg_Venus 54 "不响应ICMP请求";

     Var=`cat /proc/sys/net/ipv4/icmp_echo_ignore_all`
    
        if [ $Var -ne 0 ] ; then
            echo "已加固"
        else
            echo "未加固，现在加固"
            echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
            /sbin/sysctl -p
                fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_55(){
    Out_msg_Venus 55 "禁止IP源路由";
    
    CONF_FILE=/etc/sysctl.conf
    Chk_Conf_Backup $CONF_FILE; 
    Var=`/sbin/sysctl -a |awk -F"=" '$1~/accept_source_route/{print $2}'|sed 's/^[[:space:]]*//'`
    for i in $Var
    do
        Sum=`expr $Sum + $i`
    done
    
    if [ $Sum -ne 0 ] ; then
        echo "未加固，现在修改"
        
        for i in `/sbin/sysctl -a |awk -F"=" '$1~/accept_source_route/{print $1}'` ; do
            echo $i" = 0" >>$CONF_FILE
        done
    else
        echo "已加固"
    fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_58(){
    Out_msg_Venus 58 "apache和dhcp服务检查"
    
    RUN_LEVEL=`sed '/^#/'d /etc/inittab | sed -n '/^id/'p | awk -F: '{print $2}'`
    APACHE_STATUS=`find  /etc/rc.d/rc"$RUN_LEVEL".d -name "S*httpd*"|wc -l`

    if [ $APACHE_STATUS -ne 0 ] ; then
        echo "apache未加固,现在修改";
        /sbin/chkconfig --level $RUN_LEVEL httpd off
    else
        echo "apache已加固";
    fi

    DHCPD_STATUS=`find  /etc/rc.d/rc"$RUN_LEVEL".d -name "S*DHCPDd*"|wc -l`
    if [ $APACHE_STATUS -ne 0 ] ; then
        echo "dhcpd未加固,现在修改";
        /sbin/chkconfig --level $RUN_LEVEL dhcpd off
    else
        echo "dhcpd已加固";
    fi


    Out_msg_end;
    return 0;
}

function Venus_Linux_59(){
    Out_msg_Venus 59 "初始文件创建权限"

        CONF_FILE=/etc/profile
	Chk_Conf_Backup $CONF_FILE;
	Var=`awk '$1~/umask/&&$2~/077/' $CONF_FILE`
	
	if [ -z "$Var" ]
		then
			echo -e "未设置用户UMASK值\n现在设置......";
			echo "umask 077" >> $CONF_FILE;
	else
			echo "已设置用户UMASK值";

	fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_60(){
    Out_msg_Venus 60 "设置关键文件的属性"
    
        if [ -e /var/log/messages ] ; then
            Var=`lsattr /var/log/messages |awk '$1~/i/'|wc -l `
            
                if [ $Var -ne 1 ] ; then
                    echo "未加固，现在修改"
                    /usr/bin/chattr +a /var/log/messages
                else
                    echo "/var/log/messages已加固"
                        fi
        else
            echo "/var/log/messages文件不存在，不作修改";
                fi

        Var=`ls -l /var/log/messages*|wc -l`
        
        if [ $Var -ne 0 ] ; then
            Var2=`/usr/bin/lsattr /var/log/messages* |wc -l`
            
                if [ $Var2 -ne $Var ] ; then
                    echo "未加固,现在修改"
                    /usr/bin/chattr +i /var/log/messages.* 2>/dev/null
                else
                    echo "已加固"
                        fi
        else
            echo "/var/log/messages.*文件不存在，不作修改"
                fi
    

    Out_msg_end;
    return 0;
}

function Venus_Linux_73(){
    Out_msg_Venus 73 "对ssh、su登录日志进行记录"

    SYSLOG_CONF_FILE=/etc/syslog.conf
    Chk_Conf_Backup $SYSLOG_CONF_FILE

    Var=`grep "^authpriv\.\*" /etc/syslog.conf|wc -l`

    if [ $Var -ne 0 ] ; then
        echo "已加固"
    else
        echo "未加固，现在加固"
        echo "# The authpriv file has restricted access" >> $SYSLOG_CONF_FILE
        echo "authpriv.*    /var/log/secure">> $SYSLOG_CONF_FILE
        /etc/rc.d/init.d/syslog restart
            fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_76(){
    Out_msg_Venus 76 "指定专用的syslog服务器记录日志"

    echo "此项加固需手动修改："
    echo "需要提供日志服务器IP地址"
    echo -e "在/etc/syslog.conf文件中，\n增加syslog服务器IP地址设置：*.*\t\tsyslogserver_IPaddress，\n其中syslogserver_IPaddress是一个syslog服务器的IP地址\n并重启syslog服务，/etc/rc.d/init.d/syslog restart"

    Out_msg_end;
    return 0;
}

function Venus_Linux_81(){
    Out_msg_Venus 81 "隐藏系统提示信息"
    Chk_Conf_Backup /etc/rc.d/rc.local;
    Chk_Conf_Backup /etc/issue
    Chk_Conf_Backup /etc/issue.net

    Var=`awk '$3~/issue/' /etc/rc.d/rc.local|wc -l`

    if [ $Var -ne 2 ] ; then
        echo "未加固，现在修改"
        echo "echo > /etc/issue" >> /etc/rc.d/rc.local
        echo "echo > /etc/issue.net" >> /etc/rc.d/rc.local
        echo > /etc/issue
        echo > /etc/issue.net
    else
        echo "已加固"
            fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_82(){
    Out_msg_Venus 82 "禁止Control-Alt-Delete键盘关闭命令"
    INIT_CONF_FILE=/etc/inittab
    Chk_Conf_Backup $INIT_CONF_FILE

    Var=`grep "^ca::ctrlaltdel:/sbin/shutdown" /etc/inittab |wc -l`
    if [ $Var -ne 0 ] ; then
        echo "未加固,现在修改";
        sed -i 's/^ca\:\:ctrlaltdel\:\/sbin\/shutdown/#&/g' $INIT_CONF_FILE 
        /sbin/init q

    else
        echo "已加固";
            fi

    

    Out_msg_end;
    return 0;
}

function Venus_Linux_86(){
    Out_msg_Venus 86 "core dump 状态"

    Chk_Conf_Backup /etc/profile

    Var=` ulimit -a|awk '/core file size/{print $6}'`

    if [ $Var -ne 0 ] ; then
        echo "未加固，现在修改"
        echo "ulimit -c 0" >> /etc/profile
    else
        echo "已加固"
            fi
    

    Out_msg_end;
    return 0;
}

function Venus_Linux_88(){
    Out_msg_Venus 88 "第三方安全产品ssh安装情况"
    
    echo "检查已安装的ssh组件"
    rpm -qa | grep ssh 
    echo "检查当前ssh版本"
    ssh -V

    Out_msg_end;
    return 0;
}



function Venus_Linux_106(){
    Out_msg_Venus 106 "删除潜在危险文件"
    
    if [ -e /root/.rhosts ] ; then
      Chk_Conf_Backup /root/.rhosts
      /bin/rm  /root/.rhosts
    else
      echo "/root/.rhosts 已删除!"
    fi

    if [ -e /root/.netrc ] ; then
        Chk_Conf_Backup  /root/.netrc
        /bin/rm /root/.netrc
    else
        echo " /root/.netrc 已删除!"
    fi

    if [ -e /etc/hosts.equiv ] ; then
        Chk_Conf_Backup /etc/hosts.equiv
        /bin/rm /etc/hosts.equiv
    else
        echo "/etc/hosts.equiv 已删除!"
    fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_107(){
     Out_msg_Venus 107 "FTP匿名登录设置"

     CONF_FILE=/etc/vsftpd/vsftpd.conf
     Had_Change=`awk -F"=" '{if($1=="anonymous_enable"){print $2}}'  $CONF_FILE |tr A-Z a-z `
     
     if [ "$Had_Change" != "no" ] ; then
        Chk_Conf_Backup $CONF_FILE;
        sed -i 's/^anonymous_enable.*/#&\nanonymous_enable=NO/' $CONF_FILE;

     else
        echo $CONF_FILE"已加固" 
     fi
    
     Out_msg_end;
     return 0;
}

function Venus_Linux_109(){
    Out_msg_Venus 109 "系统banner设置"
    # mv /etc/issue /etc/issue.bak # mv /etc/issue.net /etc/issue.net.bak

    
    if [ -e /etc/issue ] && [ -e /etc/issue.net ] ; then
      Chk_Conf_Backup /etc/issue
      Chk_Conf_Backup /etc/issue.net
      /bin/rm /etc/issue
      /bin/rm /etc/issue.net
    else
      echo "已加固！"
    fi

    Out_msg_end;
    return 0;
}


function Venus_Linux_110(){
    Out_msg_Venus 110 "配置日志访问权限"

    for i in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/spooler /var/log/boot.log 
    do
      
      if [ `find $i -printf "%m" ` -ne "640" ] ; then
        echo "未加固，修改"$i"权限为640;"
	chmod 640 $i		
      else
        echo "$i已加固！"
      fi
    done
    Out_msg_end;
    return 0;
}

function Venus_Linux_111(){
  Out_msg_Venus 111 "限制远程登录"
    
  Had_Change=`awk -F"=| " '$1~/^PermitRootLogin/{print $2}' /etc/ssh/sshd_config|tr A-Z a-z`

  if [ $Had_Change != "no" ] ; then
    Chk_Conf_Backup /etc/ssh/sshd_config
    sed -i "s/^PermitRootLogin.*/#&\nPermitRootLogin no/" /etc/ssh/sshd_config
  else
    echo "已加固！"
  fi

  Out_msg_end;
  return 0;
} 

function Venus_Linux_112(){
    Out_msg_Venus 112 "禁用Telnet明文传输协议"
    
    TELNET_ON=`grep disable /etc/xinetd.d/*|grep telnet|awk '$4!~/yes/{print $1}'|tr ":" " "`

    if [ `grep disable /etc/xinetd.d/*|grep telnet|awk '$4!~/yes/{print $1}'|wc -l` -ne 0 ] ; then
      for i in $TELNET_ON
      do
        echo $i"未加固！现在加固"
        /sbin/chkconfig `basename $i` off;
        /sbin/service xinetd restart 
      done
    else
        echo "telnet已加固！"
    fi
    

}




