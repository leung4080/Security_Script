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
        if [ $SHELL_PATH -ne `awk -F ":" '$1~/^root$/{print $7}' /etc/passwd` ] ; then
            echo "root帐号shell为"`awk -F ":" '$1~/^root$/{print $7}' /etc/passwd`;
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

		Var=`awk '$0~/^PASS_MAX_DAYS/{print $2}'  /tmp/login.defs`

		if [ "$Var" == "90" ]
			then
				echo -e "已限制帐号密码限期为90天\n不作修改";
        	else
			    echo -e "未限制帐号密码限期为90天\n现在进行修改......";
                sed  -i "s/^PASS_MAX_DAYS\ *.*$/#&\nPASS_MAX_DAYS 90/" /tmp/login.defs
		fi

    Out_msg_end;
    return 0;
}
function Venus_Linux_14(){
    Out_msg_Venus 14 "密码最小有效天数";
    Chk_Conf_Backup /etc/login.defs
		Var=`awk '$0~/^PASS_MIN_DAYS/{print $2}'  /tmp/login.defs`

		if [ "$Var" == "10" ]
			then
				echo -e "已限制帐号密码最小限期为10天\n不作修改";
        	else
			    echo -e "未限制帐号密码最小限期为10天\n现在进行修改......";
                sed  -i "s/^PASS_MIN_DAYS\ *.*$/#&\nPASS_MIN_DAYS 10/" /tmp/login.defs
		fi


    Out_msg_end;
    return 0;
}
function Venus_Linux_15(){
    Out_msg_Venus 15 "密码过期提前警告天数";
    Chk_Conf_Backup /etc/login.defs

	Var=`awk '$0~/^PASS_WARN_AGE/{print $2}'  /tmp/login.defs`

		if [ "$Var" == "5" ]
			then
				echo -e "已修改密码过期提前警告天数为5天\n不作修改";
        	else
			    echo -e "未修改密码过期提前警告天数为5天\n现在进行修改......";
                sed  -i "s/^PASS_WARN_AGE\ *.*$/#&\nPASS_WARN_AGE 5/" /tmp/login.defs
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
    if [ -f /etc/vsftpd.ftpusers] ; then
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
    
    Out_msg_end;
    return 0;
}
function Venus_Linux_33(){
    Out_msg_Venus 33 "/etc/host.conf信息检查";

    Out_msg_end;
    return 0;
}
function Venus_Linux_36(){
    Out_msg_Venus 36 "不同主机间信任关系检查";

    Out_msg_end;
    return 0;
}
function Venus_Linux_38(){
    Out_msg_Venus 38 "系统ping响应信息检查";

    Out_msg_end;
    return 0;
}
function Venus_Linux_40(){
    Out_msg_Venus 40 "系统是否安装ftp信息检查";

    Out_msg_end;
    return 0;
}
function Venus_Linux_48(){
    Out_msg_Venus 48 "ftpd服务";

    Out_msg_end;
    return 0;
}
function Venus_Linux_49(){
    Out_msg_Venus 49 "fingerd服务";

    Out_msg_end;
    return 0;
}
function Venus_Linux_52(){
    Out_msg_Venus 52 "更改主机解析地址的顺序";

    Out_msg_end;
    return 0;
}
function Venus_Linux_53(){
    Out_msg_Venus 53 "打开syncookie缓解syn flood攻击";

    Out_msg_end;
    return 0;
}
function Venus_Linux_54(){
    Out_msg_Venus 54 "不响应ICMP请求";

    Out_msg_end;
    return 0;
}
function Venus_Linux_55(){
    Out_msg_Venus 55 "禁止IP源路由";

    Out_msg_end;
    return 0;
}
