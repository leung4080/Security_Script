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
        if [ $SHELL_PATH -ne `awk -F ":" '$1~/^root$/{print $7}' /etc/passwd` ] ; then
            echo "root�ʺ�shellΪ"`awk -F ":" '$1~/^root$/{print $7}' /etc/passwd`;
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

		Var=`awk '$0~/^PASS_MAX_DAYS/{print $2}'  /tmp/login.defs`

		if [ "$Var" == "90" ]
			then
				echo -e "�������ʺ���������Ϊ90��\n�����޸�";
        	else
			    echo -e "δ�����ʺ���������Ϊ90��\n���ڽ����޸�......";
                sed  -i "s/^PASS_MAX_DAYS\ *.*$/#&\nPASS_MAX_DAYS 90/" /tmp/login.defs
		fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_14(){
    Out_msg_Venus 14 "������С��Ч����";
    Chk_Conf_Backup /etc/login.defs
		Var=`awk '$0~/^PASS_MIN_DAYS/{print $2}'  /tmp/login.defs`

		if [ "$Var" == "10" ]
			then
				echo -e "�������ʺ�������С����Ϊ10��\n�����޸�";
        	else
			    echo -e "δ�����ʺ�������С����Ϊ10��\n���ڽ����޸�......";
                sed  -i "s/^PASS_MIN_DAYS\ *.*$/#&\nPASS_MIN_DAYS 10/" /tmp/login.defs
		fi


    Out_msg_end;
    return 0;
}
function Venus_Linux_15(){
    Out_msg_Venus 15 "���������ǰ��������";
    Chk_Conf_Backup /etc/login.defs

	Var=`awk '$0~/^PASS_WARN_AGE/{print $2}'  /tmp/login.defs`

		if [ "$Var" == "5" ]
			then
				echo -e "���޸����������ǰ��������Ϊ5��\n�����޸�";
        	else
			    echo -e "δ�޸����������ǰ��������Ϊ5��\n���ڽ����޸�......";
                sed  -i "s/^PASS_WARN_AGE\ *.*$/#&\nPASS_WARN_AGE 5/" /tmp/login.defs
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
    if [ -f /etc/vsftpd.ftpusers] ; then
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
    
    Out_msg_end;
    return 0;
}
function Venus_Linux_33(){
    Out_msg_Venus 33 "/etc/host.conf��Ϣ���";

    Out_msg_end;
    return 0;
}
function Venus_Linux_36(){
    Out_msg_Venus 36 "��ͬ���������ι�ϵ���";

    Out_msg_end;
    return 0;
}
function Venus_Linux_38(){
    Out_msg_Venus 38 "ϵͳping��Ӧ��Ϣ���";

    Out_msg_end;
    return 0;
}
function Venus_Linux_40(){
    Out_msg_Venus 40 "ϵͳ�Ƿ�װftp��Ϣ���";

    Out_msg_end;
    return 0;
}
function Venus_Linux_48(){
    Out_msg_Venus 48 "ftpd����";

    Out_msg_end;
    return 0;
}
function Venus_Linux_49(){
    Out_msg_Venus 49 "fingerd����";

    Out_msg_end;
    return 0;
}
function Venus_Linux_52(){
    Out_msg_Venus 52 "��������������ַ��˳��";

    Out_msg_end;
    return 0;
}
function Venus_Linux_53(){
    Out_msg_Venus 53 "��syncookie����syn flood����";

    Out_msg_end;
    return 0;
}
function Venus_Linux_54(){
    Out_msg_Venus 54 "����ӦICMP����";

    Out_msg_end;
    return 0;
}
function Venus_Linux_55(){
    Out_msg_Venus 55 "��ֹIPԴ·��";

    Out_msg_end;
    return 0;
}
