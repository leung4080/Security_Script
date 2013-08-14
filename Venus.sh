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



#=========================�����ǳ�==========================
function Venus_Linux_1(){
    Out_msg_Venus 1 "ȥ������Ҫ���ʺš��޸�Ĭ���ʺŵ�shell����"

    Chk_Conf_Backup /etc/passwd
    DEL_USER="lp sync shutdown halt  operator games gopher"
    for i in  $DEL_USER
    do
	    if [ `grep -E "^\<$i\>" /etc/passwd|wc -l ` -ne 0 ]
	    then
		    echo "�û�$i���ڣ�����ɾ����"
		    /usr/sbin/userdel $i;
		    echo "�û�$i��ɾ��";
	    else
		    echo "�û�$i��ɾ��,�����޸ġ�"
	    fi
    done

    NOLOGIN_USER="news uucp ftp";
    for i in $NOLOGIN_USER; 
    do  
        echo "check username: "$i;
        awk -F: '{if ( $1=="'$i'" && $7!~/\/sbin\/nologin|\/bin\/sync|\/sbin\/shutdown|\/sbin\/halt|\/bin\/false/  ){print "echo \"�����޸��û�"'$i'"�ĵ�½��\";usermod -s /sbin/nologin "$1}}' /etc/passwd|bash 
    done  

    echo "�Ѽӹ�"
    Out_msg_end;
    return 0;
}

function Venus_Linux_2 (){
    Out_msg_Venus 2 "passwd�ļ����"

    Chk_Conf_Backup /etc/passwd
    Chk_Conf_Backup /etc/shadow
    CHECK_SHADOW_NUM=`awk -F: '{if($2 != "x" && $2 != "*") print $1}' /etc/passwd|wc -l `
    CHECK_PASSWD_NUM=`wc -l /etc/passwd|awk '{print $1}'`

if [ $CHECK_SHADOW_NUM -ne $CHECK_PASSWD_NUM ] ; then

    NOSHADOW_USER=`awk -F: '{if($2 != "x" && $2 != "*") print $1}' /etc/passwd`
    if [ -n $NOSHADOW_USER ] 
    then
        for i in $NOSHADOW_USER; do
            echo "$i�û��쳣����ɾ�����ؽ�����������Ϊ�롰"$i"_2012����ʽ��"
                 /usr/sbin/userdel $i
                 /usr/sbin/useradd $i
                 echo $i"_2012"| /usr/bin/passwd $i --stdin
            done
    else
        echo "�Ѽӹ�"
    fi
 else
        echo -e "[error] /etc/passwd�ļ������������Զ����\n���ֶ����ϵͳ�Ƿ�����shadow����"
        return 1;
fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_3(){
    Out_msg_Venus 3 "shadow�ļ����";

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
                echo "$userδ�������룬�����޸�����Ϊ��"$user"_2012��"
	            echo $user"_2012" |/usr/bin/passwd --stdin  $user 
            fi
        done
    done
    
    echo "�Ѽӹ�"

    Out_msg_end;
    return 0;
}

function Venus_Linux_4(){
    Out_msg_Venus 4 "root�ʺ�shell������Ϣ���";
    Chk_Conf_Backup /etc/passwd
        SHELL_PATH=$(which bash) ; 
        PASSWD_ROOT_PATH=`awk -F ":" '$1~/^root$/{print $7}' /etc/passwd`
        if [ "$SHELL_PATH" != "$PASSWD_ROOT_PATH" ] ; then
            echo "root�ʺ�shellΪ"$PASSWD_ROOT_PATH;
            echo "�����޸�Ϊ$SHELL_PATH";
            /usr/sbin/usermod -s $SHELL_PATH root
        else
            echo "�Ѽӹ�";
                fi
    Out_msg_end;
    return 0;
}

function Venus_Linux_5(){
    Out_msg_Venus 5 "���ò���Ҫ���˺�";
    Chk_Conf_Backup /etc/passwd;
    Chk_Conf_Backup /etc/shadow;

    echo "do nothing!"
    echo "Venus_Linux_1���Ѽӹ�"
        
    Out_msg_end;
    return 0;
}
function Venus_Linux_9(){
    Out_msg_Venus 9 "ϵͳuid=0�ʺ���Ϣ���";
    Chk_Conf_Backup /etc/passwd
        if [ `awk -F: '{if($3==0&&$1!="root") print $1}' /etc/passwd|wc -l`  -ne 0 ] ;then
            echo "����UIDΪ0����root�����û�����ɾ���û�"
            WARN_USER=`awk -F: '{if($3==0&&$1!="root") print $1}' /etc/passwd`
            
            for i in $WARN_USER; do
                    echo $i"�û�UIDΪ0��ɾ�����û�"
                    /usr/sbin/userdel $i;
                done
        else
            echo "�Ѽӹ�"
        fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_10(){
    Out_msg_Venus 10 "ʹroot PATH���������в�������ǰĿ¼";
    Chk_Conf_Backup /etc/profile
    if [ -z "`env |awk -F "=" '$1~/^PATH$/{print $2}'|awk -F ":" '{for ( i=1;i<=NF;i++) if($i=="."){print $i}}'`" ];then
        echo "root�û����������а�����ǰĿ¼�����/etc/profile�ļ�:"
        
            if [ -z `cat /etc/profile|awk -F "=" '$1~/^PATH$/{print $2}'|awk -F ":" '{for ( i=1;i<=NF;i++) if($i=="."){print $i}}'`]  ; then
                echo "�����޸�/etc/profile�ļ�"
                sed -i '/[ ^]PATH=/s/\.://g' /etc/profile
                echo "�Ѽӹ̣������µ�½������Ч"
            else
                echo "/etc/profile��ȷ���Ѽӹ̣������µ�½�ټ��"
                    fi
    else
        echo "�Ѽӹ�"
    fi
        
    Out_msg_end;
    return 0;
}
function Venus_Linux_11(){
    Out_msg_Venus 11 "��rootΪls��rm���ñ���";

    ROOT_SHELL_FILE=~/.`basename $SHELL`rc

    Var=`grep "alias ls=" $ROOT_SHELL_FILE|head -1`
    if [ -n "$Var" ] ; then
        echo "�Ѽӹ�"
    else
        echo "δ���ls�������,�����޸�"
        echo "alias ls='ls -aol --color=tty'" >> $ROOT_SHELL_FILE
        alias ls='ls -aol --color=tty'
            fi
    Var=`grep "alias rm=" $ROOT_SHELL_FILE|head -1`
    if [ -n "$Var" ] ; then
        echo "�Ѽӹ�"
    else
        echo "δ���rm�������,�����޸�"
            echo "alias rm='rm -i'" >> $ROOT_SHELL_FILE
            alias rm='rm -i'
            fi
    Out_msg_end;
    return 0;
}
function Venus_Linux_12(){
    Out_msg_Venus 12 "ȱʡ���볤������";
    Chk_Conf_Backup /etc/login.defs
Var=`awk '$0~/^PASS_MIN_LEN/{print $2}'  /etc/login.defs`
	
    if [ $Var -ge 8 ] 
    then
       echo "�������û����볤��";
    else
        echo "δ�����û����볤��";
		sed -i "s/^PASS_MIN_LEN\ *.*$/#&/" /etc/login.defs
		echo "PASS_MIN_LEN	8" >>/etc/login.defs
    fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_13(){
    Out_msg_Venus 13 "���������Ч����";
    Chk_Conf_Backup /etc/login.defs

		Var=`awk '$0~/^PASS_MAX_DAYS/{print $2}'  /etc/login.defs`

		if [ "$Var" == "90" ]
			then
				echo -e "�������ʺ���������Ϊ90��\n�����޸�";
        	else
			    echo -e "δ�����ʺ���������Ϊ90��\n���ڽ����޸�......";
                sed  -i "s/^PASS_MAX_DAYS\ *.*$/#&\nPASS_MAX_DAYS 90/" /etc/login.defs
		fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_14(){
    Out_msg_Venus 14 "������С��Ч����";
    Chk_Conf_Backup /etc/login.defs
		Var=`awk '$0~/^PASS_MIN_DAYS/{print $2}'  /etc/login.defs`

		if [ "$Var" == "10" ]
			then
				echo -e "�������ʺ�������С����Ϊ10��\n�����޸�";
        	else
			    echo -e "δ�����ʺ�������С����Ϊ10��\n���ڽ����޸�......";
                sed  -i "s/^PASS_MIN_DAYS\ *.*$/#&\nPASS_MIN_DAYS 10/" /etc/login.defs
		fi


    Out_msg_end;
    return 0;
}
function Venus_Linux_15(){
    Out_msg_Venus 15 "���������ǰ��������";
    Chk_Conf_Backup /etc/login.defs

	Var=`awk '$0~/^PASS_WARN_AGE/{print $2}'  /etc/login.defs`

		if [ "$Var" == "5" ]
			then
				echo -e "���޸����������ǰ��������Ϊ5��\n�����޸�";
        	else
			    echo -e "δ�޸����������ǰ��������Ϊ5��\n���ڽ����޸�......";
                sed  -i "s/^PASS_WARN_AGE\ *.*$/#&\nPASS_WARN_AGE 5/" /etc/login.defs
		fi


    Out_msg_end;
    return 0;
}
function Venus_Linux_16(){
    Out_msg_Venus 16 "��ʱ�Զ�ע����¼";

    Chk_Conf_Backup /etc/profile
    Chk_Conf_Backup  /etc/environment
    Chk_Conf_Backup /etc/security/.profile
    Var=`env |awk -F"=" '$1~/TIME/{print $2}'` 
            if  [ "$Var" -ge 120 ] && [ "$Var" != "0"]; then
                echo "�Ѽӹ�"
            else
                Var2=`grep "^TMOUT=120" /etc/profile|head -1 |awk -F"=" '{print $1}'`
                    
                    if [ -z $Var2 ] ; then
                        echo "δ�ӹ̣������޸�/etc/profile��etc/environment��/etc/security/.profile�ļ�";            
                echo "TMOUT=120 ; TIMEOUT=120 ; export readonly TMOUT TIMEOUT" >> /etc/profile;
                echo "TMOUT=120 ; TIMEOUT=120 ; export readonly TMOUT TIMEOUT" >> /etc/environment;
                echo "TMOUT=120 ; TIMEOUT=120 ; export readonly TMOUT TIMEOUT" >> /etc/security/.profile;

                    else
                        echo "�Ѽӹ�"
                            fi
                            fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_19(){
    Out_msg_Venus 19 "ʹ��pasword shadowing";
    Chk_Conf_Backup /etc/passwd
    Chk_Conf_Backup /etc/shadow
    
    if [ -f /etc/shadow ] ; then
        echo "�Ѽӹ�"
    else
        echo "���ڼӹ�"
        /usr/sbin/pwconv
            fi
    Out_msg_end;
    return 0;
}
function Venus_Linux_20(){
    Out_msg_Venus 20 "��֤bash shell���������ģ��򲻱��棩����";
    Chk_Conf_Backup /etc/profile
    
    HFS=`grep "HISTFILESIZE=30" /etc/profile`
    HS=`grep "HISTSIZE=30" /etc/profile`
        if [ -n "$HFS" ] && [ -n "$HS" ] ; then
            echo "�Ѽӹ�";
        else
            echo "δ�ӹ̣������޸�/etc/profile�ļ�"
            echo -e "HISTFILESIZE=30\nHISTSIZE=30" >> /etc/profile
                fi


    Out_msg_end;
    return 0;
}
function Venus_Linux_21(){
    Out_msg_Venus 21 "ʹ��PAM��ֹ�κ���suΪroot";
    echo "[warnning��]�˼ӹ�����ڽϴ���գ������޸���ο����·������ֶ����ã�"
    echo "1,������su��root���û���ӵ�wheel��(i.e��test�û���ӵ�wheel��):#usermod -G wheel test"
    echo "2,����/etc/pam.d/su�ļ�"
    echo "3,��/etc/pam.d/su�ļ���#auth           required        pam_wheel.so use_uid�е�ע�ͷ���#��ɾ��"
    echo "4,ʹ�������û�su����֤�����Ƿ�ɹ�"
    Out_msg_end;
    return 0;
}
function Venus_Linux_22(){
    Out_msg_Venus 22 "��ֹʹ��ftp���ʺż��";
    Chk_Conf_Backup /etc/vsftpd/ftpusers
    Chk_Conf_Backup /etc/vsftpd.ftpusers

    if [ -f /etc/vsftpd.ftpusers ] ; then
        Var=`cat /etc/vsftpd.ftpusers|wc -l` 
        if [ $Var -ne 0 ] ; then
            echo "�Ѽӹ�"
        fi
    else
        echo "δ�ӹ̣������޸ġ�"
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
    Out_msg_Venus 32 "xinetd/inetd������Ϣ���";

    INET=`rpm -qa | grep xinetd`
    INET_NAME=`echo $INET|awk -F"-" '{print $1}'`
    if [ -z $INET ] ;then
        echo "δ��װxinetd��inetd�����Ȱ�װxinetd��inetd���!"��
        return 1;
    fi
    INET_SCRIPT=`rpm -ql $INET |grep "^/etc/rc.*inetd"`
    $INET_SCRIPT status;
    RETVAL=$?
    if [ $RETVAL -ne 0 ] ;then
        echo "$INET_NAMEδ����";
        echo "��������$INET_NAME"
        $INET_SCRIPT start ;
        /sbin/chkconfig $INET_NAME on
    else
        echo "$INET_NAME���������Ѽӹ�"
    fi
    
    Out_msg_end;
    return 0;
}
function Venus_Linux_33(){
    Out_msg_Venus 33 "/etc/host.conf��Ϣ���";

    CONF_FILE=/etc/host.conf
    Chk_Conf_Backup $CONF_FILE;
    Var=`grep "order hosts,bind" $CONF_FILE |wc -l`
    
        if [ $Var -ne 0 ] ; then
            echo "�Ѽӹ�"
        else
            echo "δ�ӹ̣������޸�$CONF_FILE�ļ�"
            echo "order hosts,bind">> $CONF_FILE;
                fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_36(){
    Out_msg_Venus 36 "��ͬ���������ι�ϵ���";
    CONF_FILE=/etc/hosts.equiv

    if [ -f $CONF_FILE ] ;then
        echo "δ�ӹ�,����ɾ��$CONF_FILE�ļ�";
    	Chk_Conf_Backup $CONF_FILE; 
        rm -f $CONF_FILE;
    else
        echo "�Ѽӹ�"
    fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_38(){
    Out_msg_Venus 38 "ϵͳping��Ӧ��Ϣ���";
    Var=`cat /proc/sys/net/ipv4/icmp_echo_ignore_all`
    
        if [ $Var -ne 0 ] ; then
            echo "�Ѽӹ�"
        else
            echo "δ�ӹ̣����ڼӹ�"
            echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
            /sbin/sysctl -p
                fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_40(){
    Out_msg_Venus 40 "ϵͳ�Ƿ�װftp��Ϣ���";

    Var=` rpm -qa | grep ftp|wc -l` 
    Var2=`ls /etc/xinetd.d/*ftp*|wc -l`
    
    if [ $Var -gt 0 ] && [ $Var2 -gt 0 ] ; then
       echo "�Ѽӹ�"
    else
       echo "δ�ӹ�,���ֶ���װftp���"
    fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_48(){
    Out_msg_Venus 48 "ftpd����";

    Chk_Conf_Backup /etc/syslog.conf;
    if [ -f /etc/rc.d/init.d/xinetd ] ; then
        test 
    else
        echo "xinetd�����ļ������ڣ�����xinetd�Ƿ���ȷ��װ"
        return 1;
    fi
    
    Var=`grep -v "#" /etc/xinetd.d/* | grep "service ftp"|wc -l` 
    if [ $Var -ne 0 ] ; then
       LOOP=`grep -v "#" /etc/xinetd.d/* | grep "service ftp" |awk -F":" '{print $1}'`
       
       for FTP_FILE_CONF in $LOOP; do
            VAR_FF=`awk '/^[^#].*server_args/&&/-l/&&/-r/&&/-A/&&/-S/' $FTP_FILE_CONF|wc -l`
            if [ $VAR_FF -ne 0 ] ; then
                echo "$FTP_FILE_CONF�Ѽӹ�"
            else
                echo "$FTP_FILE_CONFδ�ӹ�,�����޸�"
		sed -i 's/server_args.*/server_args\t= -l -r -A -S/' $FTP_FILE_CONF
		#sed -i ':a;N;$!ba;s/(.*\n)(.*})/\1server_args = -l -r -A -S\n\2/' $FTP_FILE_CONF;
            fi
       done
    else
        echo "δ�ҵ�ftp��������ļ������ֶ����/etc/xinetd.d/���Ƿ����ftp�����ļ�"
        return 1;
    fi

    Var=`grep "^ftp" /etc/syslog.conf|wc -l`
    
    if [ -n $var ] ; then
        echo "/etc/syslog.conf�Ѽӹ�"
    else
        echo "/etc/syslog.confδ�ӹ̣����ڼӹ�"
        echo "ftp.*  /var/log/ftpd" >>/etc/syslog.conf
    fi

        
    Out_msg_end;
    return 0;
}
function Venus_Linux_49(){
    Out_msg_Venus 49 "fingerd����";
    
    if [ -f /etc/xinetd.d/finger ] ; then
        # /etc/xinetd.d/finger exist; 
        Var=`grep disable /etc/xinetd.d/auth |awk -F"=" '{print $2}'|sed 's/^[[:space:]]*//'`
        if [ $Var = "yes" ]; then
            echo "�Ѽӹ�"
        else
            echo "δ�ӹ̣������޸�"
            sed 's/^.*disable.*=.*no.*/\tdisable\t\t= yes/g' /etc/xinetd.d/finger
        fi
    else
        # /etc/xinetd.d/finger not exist;
        echo "[warn]/etc/xinetd.d/finger not exist,�޷��ӹ�"
    fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_52(){
    Out_msg_Venus 52 "��������������ַ��˳��";
    
    CONF_FILE=/etc/host.conf

    Chk_Conf_Backup $CONF_FILE;

    Var=`awk '$0~/order.*hosts.*bind.*/' $CONF_FILE|wc -l `

        if [ -n $var ] ; then
            echo "�Ѽӹ�"
        else
            echo "δ�ӹ�,�����޸�"
            echo "order hosts��bind" >>$CONF_FILE;
            echo "multi on" >>$CONF_FILE
            echo "nospoof on" >>$CONF_FILE
                fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_53(){
    Out_msg_Venus 53 "��syncookie����syn flood����";

    CONF_FILE=/etc/sysctl.conf
    Chk_Conf_Backup $CONF_FILE
    Var=`cat /proc/sys/net/ipv4/tcp_syncookies`
    
    if [ $Var -ne 1 ] ; then
        echo "δ�ӹ̣������޸�"
        echo "net.ipv4.tcp_syncookies = 1">>$CONF_FILE
        /sbin/sysctl -p
    else
        echo "�Ѽӹ�";
            fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_54(){
    Out_msg_Venus 54 "����ӦICMP����";

     Var=`cat /proc/sys/net/ipv4/icmp_echo_ignore_all`
    
        if [ $Var -ne 0 ] ; then
            echo "�Ѽӹ�"
        else
            echo "δ�ӹ̣����ڼӹ�"
            echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
            /sbin/sysctl -p
                fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_55(){
    Out_msg_Venus 55 "��ֹIPԴ·��";
    
    CONF_FILE=/etc/sysctl.conf
    Chk_Conf_Backup $CONF_FILE; 
    Var=`/sbin/sysctl -a |awk -F"=" '$1~/accept_source_route/{print $2}'|sed 's/^[[:space:]]*//'`
    for i in $Var
    do
        Sum=`expr $Sum + $i`
    done
    
    if [ $Sum -ne 0 ] ; then
        echo "δ�ӹ̣������޸�"
        
        for i in `/sbin/sysctl -a |awk -F"=" '$1~/accept_source_route/{print $1}'` ; do
            echo $i" = 0" >>$CONF_FILE
        done
    else
        echo "�Ѽӹ�"
    fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_58(){
    Out_msg_Venus 58 "apache��dhcp������"
    
    RUN_LEVEL=`sed '/^#/'d /etc/inittab | sed -n '/^id/'p | awk -F: '{print $2}'`
    APACHE_STATUS=`find  /etc/rc.d/rc"$RUN_LEVEL".d -name "S*httpd*"|wc -l`

    if [ $APACHE_STATUS -ne 0 ] ; then
        echo "apacheδ�ӹ�,�����޸�";
        /sbin/chkconfig --level $RUN_LEVEL httpd off
    else
        echo "apache�Ѽӹ�";
    fi

    DHCPD_STATUS=`find  /etc/rc.d/rc"$RUN_LEVEL".d -name "S*DHCPDd*"|wc -l`
    if [ $APACHE_STATUS -ne 0 ] ; then
        echo "dhcpdδ�ӹ�,�����޸�";
        /sbin/chkconfig --level $RUN_LEVEL dhcpd off
    else
        echo "dhcpd�Ѽӹ�";
    fi


    Out_msg_end;
    return 0;
}

function Venus_Linux_59(){
    Out_msg_Venus 59 "��ʼ�ļ�����Ȩ��"

        CONF_FILE=/etc/profile
	Chk_Conf_Backup $CONF_FILE;
	Var=`awk '$1~/umask/&&$2~/077/' $CONF_FILE`
	
	if [ -z "$Var" ]
		then
			echo -e "δ�����û�UMASKֵ\n��������......";
			echo "umask 077" >> $CONF_FILE;
	else
			echo "�������û�UMASKֵ";

	fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_60(){
    Out_msg_Venus 60 "���ùؼ��ļ�������"
    
        if [ -e /var/log/messages ] ; then
            Var=`lsattr /var/log/messages |awk '$1~/i/'|wc -l `
            
                if [ $Var -ne 1 ] ; then
                    echo "δ�ӹ̣������޸�"
                    /usr/bin/chattr +a /var/log/messages
                else
                    echo "/var/log/messages�Ѽӹ�"
                        fi
        else
            echo "/var/log/messages�ļ������ڣ������޸�";
                fi

        Var=`ls -l /var/log/messages*|wc -l`
        
        if [ $Var -ne 0 ] ; then
            Var2=`/usr/bin/lsattr /var/log/messages* |wc -l`
            
                if [ $Var2 -ne $Var ] ; then
                    echo "δ�ӹ�,�����޸�"
                    /usr/bin/chattr +i /var/log/messages.* 2>/dev/null
                else
                    echo "�Ѽӹ�"
                        fi
        else
            echo "/var/log/messages.*�ļ������ڣ������޸�"
                fi
    

    Out_msg_end;
    return 0;
}

function Venus_Linux_73(){
    Out_msg_Venus 73 "��ssh��su��¼��־���м�¼"

    SYSLOG_CONF_FILE=/etc/syslog.conf
    Chk_Conf_Backup $SYSLOG_CONF_FILE

    Var=`grep "^authpriv\.\*" /etc/syslog.conf|wc -l`

    if [ $Var -ne 0 ] ; then
        echo "�Ѽӹ�"
    else
        echo "δ�ӹ̣����ڼӹ�"
        echo "# The authpriv file has restricted access" >> $SYSLOG_CONF_FILE
        echo "authpriv.*    /var/log/secure">> $SYSLOG_CONF_FILE
        /etc/rc.d/init.d/syslog restart
            fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_76(){
    Out_msg_Venus 76 "ָ��ר�õ�syslog��������¼��־"

    echo "����ӹ����ֶ��޸ģ�"
    echo "��Ҫ�ṩ��־������IP��ַ"
    echo -e "��/etc/syslog.conf�ļ��У�\n����syslog������IP��ַ���ã�*.*\t\tsyslogserver_IPaddress��\n����syslogserver_IPaddress��һ��syslog��������IP��ַ\n������syslog����/etc/rc.d/init.d/syslog restart"

    Out_msg_end;
    return 0;
}

function Venus_Linux_81(){
    Out_msg_Venus 81 "����ϵͳ��ʾ��Ϣ"
    Chk_Conf_Backup /etc/rc.d/rc.local;
    Chk_Conf_Backup /etc/issue
    Chk_Conf_Backup /etc/issue.net

    Var=`awk '$3~/issue/' /etc/rc.d/rc.local|wc -l`

    if [ $Var -ne 2 ] ; then
        echo "δ�ӹ̣������޸�"
        echo "echo > /etc/issue" >> /etc/rc.d/rc.local
        echo "echo > /etc/issue.net" >> /etc/rc.d/rc.local
        echo > /etc/issue
        echo > /etc/issue.net
    else
        echo "�Ѽӹ�"
            fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_82(){
    Out_msg_Venus 82 "��ֹControl-Alt-Delete���̹ر�����"
    INIT_CONF_FILE=/etc/inittab
    Chk_Conf_Backup $INIT_CONF_FILE

    Var=`grep "^ca::ctrlaltdel:/sbin/shutdown" /etc/inittab |wc -l`
    if [ $Var -ne 0 ] ; then
        echo "δ�ӹ�,�����޸�";
        sed -i 's/^ca\:\:ctrlaltdel\:\/sbin\/shutdown/#&/g' $INIT_CONF_FILE 
        /sbin/init q

    else
        echo "�Ѽӹ�";
            fi

    

    Out_msg_end;
    return 0;
}

function Venus_Linux_86(){
    Out_msg_Venus 86 "core dump ״̬"

    Chk_Conf_Backup /etc/profile

    Var=` ulimit -a|awk '/core file size/{print $6}'`

    if [ $Var -ne 0 ] ; then
        echo "δ�ӹ̣������޸�"
        echo "ulimit -c 0" >> /etc/profile
    else
        echo "�Ѽӹ�"
            fi
    

    Out_msg_end;
    return 0;
}

function Venus_Linux_88(){
    Out_msg_Venus 88 "��������ȫ��Ʒssh��װ���"
    
    echo "����Ѱ�װ��ssh���"
    rpm -qa | grep ssh 
    echo "��鵱ǰssh�汾"
    ssh -V

    Out_msg_end;
    return 0;
}



function Venus_Linux_106(){
    Out_msg_Venus 106 "ɾ��Ǳ��Σ���ļ�"
    
    if [ -e /root/.rhosts ] ; then
      Chk_Conf_Backup /root/.rhosts
      /bin/rm  /root/.rhosts
    else
      echo "/root/.rhosts ��ɾ��!"
    fi

    if [ -e /root/.netrc ] ; then
        Chk_Conf_Backup  /root/.netrc
        /bin/rm /root/.netrc
    else
        echo " /root/.netrc ��ɾ��!"
    fi

    if [ -e /etc/hosts.equiv ] ; then
        Chk_Conf_Backup /etc/hosts.equiv
        /bin/rm /etc/hosts.equiv
    else
        echo "/etc/hosts.equiv ��ɾ��!"
    fi

    Out_msg_end;
    return 0;
}

function Venus_Linux_107(){
     Out_msg_Venus 107 "FTP������¼����"

     CONF_FILE=/etc/vsftpd/vsftpd.conf
     Had_Change=`awk -F"=" '{if($1=="anonymous_enable"){print $2}}'  $CONF_FILE |tr A-Z a-z `
     
     if [ "$Had_Change" != "no" ] ; then
        Chk_Conf_Backup $CONF_FILE;
        sed -i 's/^anonymous_enable.*/#&\nanonymous_enable=NO/' $CONF_FILE;

     else
        echo $CONF_FILE"�Ѽӹ�" 
     fi
    
     Out_msg_end;
     return 0;
}

function Venus_Linux_109(){
    Out_msg_Venus 109 "ϵͳbanner����"
    # mv /etc/issue /etc/issue.bak # mv /etc/issue.net /etc/issue.net.bak

    
    if [ -e /etc/issue ] && [ -e /etc/issue.net ] ; then
      Chk_Conf_Backup /etc/issue
      Chk_Conf_Backup /etc/issue.net
      /bin/rm /etc/issue
      /bin/rm /etc/issue.net
    else
      echo "�Ѽӹ̣�"
    fi

    Out_msg_end;
    return 0;
}


function Venus_Linux_110(){
    Out_msg_Venus 110 "������־����Ȩ��"

    for i in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/spooler /var/log/boot.log 
    do
      
      if [ `find $i -printf "%m" ` -ne "640" ] ; then
        echo "δ�ӹ̣��޸�"$i"Ȩ��Ϊ640;"
	chmod 640 $i		
      else
        echo "$i�Ѽӹ̣�"
      fi
    done
    Out_msg_end;
    return 0;
}

function Venus_Linux_111(){
  Out_msg_Venus 111 "����Զ�̵�¼"
    
  Had_Change=`awk -F"=| " '$1~/^PermitRootLogin/{print $2}' /etc/ssh/sshd_config|tr A-Z a-z`

  if [ $Had_Change != "no" ] ; then
    Chk_Conf_Backup /etc/ssh/sshd_config
    sed -i "s/^PermitRootLogin.*/#&\nPermitRootLogin no/" /etc/ssh/sshd_config
  else
    echo "�Ѽӹ̣�"
  fi

  Out_msg_end;
  return 0;
} 

function Venus_Linux_112(){
    Out_msg_Venus 112 "����Telnet���Ĵ���Э��"
    
    TELNET_ON=`grep disable /etc/xinetd.d/*|grep telnet|awk '$4!~/yes/{print $1}'|tr ":" " "`

    if [ `grep disable /etc/xinetd.d/*|grep telnet|awk '$4!~/yes/{print $1}'|wc -l` -ne 0 ] ; then
      for i in $TELNET_ON
      do
        echo $i"δ�ӹ̣����ڼӹ�"
        /sbin/chkconfig `basename $i` off;
        /sbin/service xinetd restart 
      done
    else
        echo "telnet�Ѽӹ̣�"
    fi
    

}




