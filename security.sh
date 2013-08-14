#!/bin/bash - 
#===============================================================================
#
#          FILE: security.sh
# 
#         USAGE: ./security.sh 
# 
#   DESCRIPTION: ��ȫ�ӹ̽ű� 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: LiangHuiQiang (), Leung4080@gmail.com
#  ORGANIZATION: 
#       CREATED: 2013/8/2 14:42:35 �й���׼ʱ��
#      REVISION:  ---
#===============================================================================

#set -o nounset                              # Treat unset variables as an error

#��ҪrootȨ��ִ�У�
test "$(whoami)" != 'root' && (echo you are using a non-privileged account , please run as root ! ; exit 1)

#����LANG
LANG=c
export LANG

#��ȡ��ǰ���ڣ�
DATE=`date +%Y%m%d`

#����ű�����Ŀ¼
cd `dirname $0`;


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  Out_msg_head
#   DESCRIPTION:  �����ȫ�ӹ��������
#    PARAMETERS:  $1:�ڼ��$2:������
#       RETURNS:  ��
#-------------------------------------------------------------------------------
function Out_msg_head(){
  NUM=$1
	DESCRIPTION=$2
	
    
  echo "==linux-��ȫҪ��-�豸-ͨ��-����-$NUM===="
    

  echo -e $DESCRIPTION
  echo "====================================="

}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  Out_msg_end
#   DESCRIPTION:  ��ʾ��ȫ���Ѽӹ�
#    PARAMETERS:  
#       RETURNS:  
#-------------------------------------------------------------------------------
function Out_msg_end(){

     echo "--------CHECKED--------"
}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  Chk_Conf_Backup
#   DESCRIPTION:  �������Ƿ��Ѿ����ݹ������ļ������û���򱸷�
#    PARAMETERS:  $1:�����ļ� 
#       RETURNS:  
#-------------------------------------------------------------------------------
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


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  BACKUP_SYS_CONF
#   DESCRIPTION:  ������Ҫ��ϵͳ���ã�
#    PARAMETERS:  ��
#       RETURNS:  
#-------------------------------------------------------------------------------
function BACKUP_SYS_CONF(){

	Chk_Conf_Backup /etc/passwd;	
  Chk_Conf_Backup /etc/securetty;
	Chk_Conf_Backup /etc/ssh/sshd_config;
	Chk_Conf_Backup /etc/login.defs
	return 0;

}




#-------------------------------------------------------------------------------
#         ���������ȫ�ӹ���
#-------------------------------------------------------------------------------



#linux-��ȫҪ��-�豸-ͨ��-����-1 

function Check_Linux_1(){
    Out_msg_head 1 "�޸��û���Ŀ¼Ȩ��";

    awk -F":" '($3==0 || $3>=500 ) && $6!~/(\/var|\/usr|\/sbin|\/etc|\/dev|\/bin|^\/$)/{print $6}' /etc/passwd|uniq|xargs -i find {} -maxdepth 0 -printf "echo \"chmod %m %p\";chmod %m %p\n" 2>/dev/null |bash 
    
    Out_msg_end;
    return 0;
}

#linux-��ȫҪ��-�豸-ͨ��-����-2
function Check_Linux_2(){

    Out_msg_head 2 "ɾ�����������豸���С�ά���ȹ����޹ص��˺š�"
    
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

    Out_msg_head 3 "���ƾ߱���������ԱȨ�޵��û�Զ�̵�¼";


    echo "����Ƿ�����root�û�Զ��telnet��¼��"��
    Var=`grep -i "^CONSOLE=/dev/tty01$" /etc/securetty`
    if [ -n "$Var" ] 
     then
        echo "������telnet";
    else
        echo "δ���ƣ������޸�:";
		echo "CONSOLE=/dev/tty01" >> /etc/securetty;
		Var_telnet=`grep "disable" /etc/xinetd.d/telnet |awk -F"=" '{print $2}'`

		if [ $Var_telnet == "no" ]
		then
		/etc/init.d/xinetd restart
		fi
		echo "���";
    fi

    echo "����Ƿ�����root�û�ֱ��Զ��ssh��¼:"
    Var=`grep -i "^PermitRootLogin.*\ no" /etc/ssh/sshd_config`
     if [ -n "$Var" ] 
     then
       echo "������ssh";
    else
        echo "δ����ssh";
		echo "PermitRootLogin no" >> /etc/ssh/sshd_config;
		/etc/init.d/sshd restart ;
    fi

    Out_msg_end;
    return 0;
}
function Check_Linux_4(){

    Out_msg_head 4 "����ϵͳҪ���û���ҵ�����󣬽������ʻ��飬���û��˺ŷ��䵽��Ӧ���ʻ��顣"
	#do not something;
    echo "���ֶ����"
    Out_msg_end;
	return 0;
}

function Check_Linux_5(){
    Out_msg_head 5 "��ϵͳ�˺Ž��е�¼���ƣ�ȷ��ϵͳ�˺Ž����ػ����̺ͷ���ʹ�ã���Ӧֱ���ɸ��˺ŵ�¼ϵͳ�����ϵͳû��Ӧ����Щ�ػ����̻����Ӧɾ����Щ�˺š�"
	#do not something;
    echo "���ֶ����";
    Out_msg_end;
	return 0;
}


function Check_Linux_6(){

    Out_msg_head 6 "���ڲ��þ�̬������֤�������豸�����������8λ�����������֡�Сд��ĸ����д��ĸ���������4��������3�ࡣ"
	
	Chk_Conf_Backup /etc/login.defs;
    Chk_Conf_Backup /etc/pam.d/system-auth; 

    Var=`awk '$0~/^PASS_MIN_LEN/{print $2}'  /etc/login.defs`
	
    if [ $Var -ge 8 ] 
    then
       echo "�������û����볤��";
    else
        echo "δ�����û����볤��";
		sed -i "s/^PASS_MIN_LEN\ *.*$/#&/" /etc/login.defs
		echo "PASS_MIN_LEN	8" >>/etc/login.defs
    fi

	Var=`awk '$1~/^password/&&$2~/requisite/&&$0~/difok=1/&&$0~/lcredit=1/&&$0~/ucredit=1/&&$0~/credit=1/{print $0}' /etc/pam.d/system-auth`
	if [ -z "$Var" ]
	then
			echo "δ�����û�����ǿ��";
		
			sed -i 's/password.*requisite.*$/#&\npassword    requisite     pam_cracklib.so retry=6 difok=1 lcredit=1 ucredit=1 credit=1/g' /etc/pam.d/system-auth
	else
			echo "�������û�����ǿ��";
	fi
	Out_msg_end;

}
function Check_Linux_7(){

	    Out_msg_head 7 "���ڲ��þ�̬������֤�������豸���ʻ�����������ڲ�����90�졣"

			    Chk_Conf_Backup /etc/login.defs;
	
		Var=`awk '$0~/^PASS_MAX_DAYS/{print $2}'  /etc/login.defs`

		if [ "$Var" == "90" ]
			then
				echo -e "�������ʺ���������Ϊ90��\n�����޸�";
        	else
			    echo -e "δ�����ʺ���������Ϊ90��\n���ڽ����޸�......";
                sed  -i "s/^PASS_MAX_DAYS\ *.*$/#&\nPASS_MAX_DAYS 90/" /etc/login.defs
		fi
		
		Out_msg_end;

}

function Check_Linux_8(){
		Out_msg_head 8 "���ڲ��þ�̬������֤�������豸��Ӧ���õ��û�������֤ʧ�ܴ�������6�Σ�����6�Σ����������û�ʹ�õ��˺š�"
		CONF_FILE=/etc/pam.d/system-auth
		Chk_Conf_Backup $CONF_FILE 
		Var=`awk '$1~/^password/&&$2~/requisite/&&$0~/retry=6/{print $0}' $CONF_FILE`
		
		if [ -z "$Var" ]
			then
				echo "δ�����û�����ǿ��";
		        sed  's/password.*requisite.*$/#&\npassword    requisite     pam_cracklib.so retry=6 difok=1 lcredit=1 ucredit=1 credit=1/g' $CONF_FILE 
	    else
	            echo "�������û�����ǿ��";
	    fi

		Out_msg_end;

}

function Check_Linux_9(){
	Out_msg_head 9 "���豸Ȩ�����������ڣ������û���ҵ����Ҫ���������������СȨ�ޡ�"

	echo "do nothing"

	Out_msg_end;

}

function Check_Linux_10(){
	Out_msg_head 10 "�����û�ȱʡ����Ȩ�ޣ����ڴ������ļ���Ŀ¼ʱ Ӧ���ε����ļ���Ŀ¼��Ӧ�еķ�������Ȩ�ޡ�\n��ֹͬ���ڸ���������û����������û��޸ĸ��û����ļ����������";
	CONF_FILE=/etc/profile
	Chk_Conf_Backup $CONF_FILE;
	Var=`awk '$1~/umask/' $CONF_FILE`
	
	if [ -z "$Var" ]
		then
			echo -e "δ�����û�UMASKֵ\n��������......";
			echo "umask 027" >> $CONF_FILE;
	else
			echo "�������û�UMASKֵ";

	fi

	Out_msg_end;
}

function Check_Linux_11(){
	    Out_msg_head 11 "����FTP����ȱʡ����Ȩ��\n��ͨ��FTP���񴴽����ļ���Ŀ¼ʱӦ���ε����ļ���Ŀ¼��Ӧ�еķ�������Ȩ�ޡ�";

 
        if [ -f /etc/ftpusers ] ; then
            FTPUSERS_FILE=/etc/ftpusers
            FTPACCESS_FILE=/etc/ftpaccess
        else
            if [ -d /etc/ftpd ] ; then
            FTPUSERS_FILE=/etc/ftpd/ftpusers
            FTPACCESS_FILE=/etc/ftpd/ftpaccess
            else
                "/etc/ftpusers��/etc/ftpd/ftpusers�����ڣ������Ƿ��Ѱ�װftp"
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
	    Out_msg_head 12 "�豸Ӧ������־���ܣ����û���¼���м�¼����¼���ݰ������ٰ���������ڡ�ʱ�䡢��������Ϣ��������͡�������������ͽ����Ҫ�ء�";

      SYSLOG_PACKAGE=` LANG=c /sbin/chkconfig --list|grep syslog|grep on|awk '{print $1}'  LANG=c /sbin/chkconfig --list|grep syslog|grep on|awk '{print $1}' `
        if [ -z $SYSLOG_PACKAGE ];
        then

            echo " δ�ҵ�syslog����! ����Ƿ�������syslog(��rsyslog)";
            echo "�볢��ʹ��service syslog start�����ÿ�������chkconfig syslog on"
            echo "��service rsyslog restart��chkconfig rsyslog on"
            return 1;
        else
             SYSLOG_CONF_FILE=`rpm -qa|grep  $SYSLOG_PACKAGE|xargs -i rpm -ql {} |grep '.*conf$'|head -1`
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
	    Out_msg_head 13 "�豸Ӧ������־���ܣ���¼�����豸��صİ�ȫ�¼���";
        SYSLOG_PACKAGE=`ps -ef|grep syslog |grep -v grep |awk '{print $8}'|xargs which|xargs rpm -qf|head -1`

        if [ -z $SYSLOG_PACKAGE ];
        then
            echo " δ�ҵ�syslog����! ����Ƿ�������syslog(��rsyslog)";
            echo "�볢��ʹ��service syslog start�����ÿ�������chkconfig syslog on"
            echo "��service rsyslog restart��chkconfig rsyslog on"
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
	    Out_msg_head 14 "[��ѡ]�豸����Զ����־���ܣ�����Ҫ�ص��ע����־���ݴ��䵽��־��������";
        echo "���ֶ��޸�/etc/syslog.conf����rsyslog.conf����"
        echo -e "�������¼��У�\nauth.info\t\t@loghost  \n*.info;auth.none\t\t@loghost  \n*.emerg\t\t@loghost  \nlocal7.*\t\t@loghost"
        echo "����loghostΪ��־������ip��"
		    Out_msg_end;
}

function Check_Linux_15(){
	    Out_msg_head 15 "����ʹ��IPЭ�����Զ��ά�����豸���豸Ӧ����ʹ��SSH�ȼ���Э�飬����ȫ����SSHD�����á�";

        service sshd restart;
            
		    Out_msg_end;
}

function Check_Linux_16(){
	    Out_msg_head 16 "�豸Ӧ֧���г����⿪�ŵ�IP����˿ں��豸�ڲ����̵Ķ�Ӧ��";
        echo -e "���ֶ���飺\n1,���ŵķ����б�,����:  # chkconfig --list\n2,���ŵĶ˿��б�,����:  # netstat -an\n3,����˿ںͽ��̶�Ӧ��,���#cat  /etc/services"
		    Out_msg_end;
}

function Check_Linux_17(){
	    Out_msg_head 17 "����ͨ��IPЭ�����Զ��ά�����豸���豸Ӧ֧�ֶ������½�����豸��IP��ַ��Χ�����趨��";

        echo -e "���ֶ���飺\n1,������ʵ�IP�б�#cat /etc/hosts.allow\n2,��ֹ���ʵ�IP�б�#cat /etc/hosts.deny"
		    Out_msg_end;
}

function Check_Linux_18(){
        Out_msg_head 18 "����ϵͳӦ�ý�ֹICMP�ض��򣬲��þ�̬·��"
        
        Var=`sysctl -a|awk '$1~/net.ipv4.conf.all.accept_redirects/{print $3}'`
        
        if [ "$Var" != "0" ] ; then
            echo -e "δ��ֹICMP�ض���;\n�����޸�......" 
            Chk_Conf_Backup /etc/sysctl.conf
            echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
            sysctl -p;
        else
            echo "�ѽ�ֹICMP�ض���"
        fi


        Out_msg_end;
}

function Check_Linux_19(){
    Out_msg_head 19 "���ڲ���·�ɹ��ܵ�ϵͳ��Ӧ�ùر����ݰ�ת�����ܡ�"
    Var=`sysctl -a|awk '$1~/net.ipv4.ip_forward/{print $3}'`
        
        if [ "$Var" != "0" ] ; then
            echo -e "δ�ر����ݰ�ת������" 
            Chk_Conf_Backup /etc/sysctl.conf
            echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
            sysctl -p;
        else
            echo "�ѹر����ݰ�ת������"
        fi
 
    Out_msg_end;
}

function Check_Linux_20(){
    Out_msg_head 20 "���ھ߱��ַ�����������豸��Ӧ���ö�ʱ�ʻ��Զ��ǳ�";
    
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
function Check_Linux_21(){
    Out_msg_head 21 "���ھ߱�ͼ�ν��棨��WEB���棩���豸��Ӧ���ö�ʱ�Զ���Ļ������"
    
        Chk_Conf_Backup /etc/profile
    Var=`awk '$1~/^setterm/{print $3}' /etc/profile`;
        
    if [ "$Var" == "1" ] ; then
        echo "�Ѽӹ̣�"
    else
        echo "δ�ӹ̣������޸�/etc/profile�ļ�";
        echo "setterm -blank 1" >> /etc/profile;
    fi
        
    Out_msg_end;
    return 0;
}

function Check_Linux_22(){
    Out_msg_head 22 "�漰�˺š��˺��顢�������ȵ���Ҫ�ļ���Ŀ¼��Ȩ�����ò��ܱ�������Աɾ�����޸ġ�"
    
Var=` find /etc/rc.d/init.d/ -maxdepth 1 -mindepth 1 ! -user root  |head -1`
if [ -z $Var ] ;
then
	echo "/etc/rc.d/init.d/�������ļ�������Ϊroot�������޸ġ�"
else
	for i in `find /etc/rc.d/init.d/ -maxdepth 1 -mindepth 1 ! -user root`; 
	do 
	echo -e "����ļ���"$i
	echo -e "�ļ���������root\t�����޸�...";
	chown root $i;
	echo "���޸�"
	done
fi


Var=`find /etc/rc.d/init.d/ -maxdepth 1 -mindepth 1 ! -perm 750 -o ! -user root  |head -1`; 
if [ -z $Var ] ;
then
	echo "/etc/rc.d/init.d/�������ļ�Ȩ��Ϊ750"
else 
	for i in `find /etc/rc.d/init.d/ -maxdepth 1 -mindepth 1 ! -perm 750`; 
	do 
	echo -e "����ļ���"$i
	echo -e "�ļ�Ȩ�޲���750\t�����޸�..."
	chmod 750 $i ��
	echo -e "���޸�Ϊ750��";
	done
fi

    Out_msg_end;
}

function Check_Linux_23(){
    Out_msg_head 23 "Ӧ�ô�Ӧ�ò�����б�Ҫ�İ�ȫ���ʿ��ƣ�����FTP������Ӧ������ftp����ʹ�õ�Ŀ¼��Χ��"

    echo "do nothing!"
    #do nothings    

    Out_msg_end;
    return 0
}

function Check_Linux_24(){
    Out_msg_head 24 "��ϵͳ��װʱ����ֻ��װ������OS���ݣ��������������Ա�ҪΪԭ�򣬷Ǳ���İ��Ͳ�װ��"

echo -e "ִ����������鿴�汾���󲹶��š�\n#uname �Ca\nִ����������鿴�����Ĳ�����\n#rpm -qa\n" 

    Out_msg_end
    return 0;
}

function Check_Linux_25(){
    Out_msg_head 25 "Ӧ������Ҫ��ʱ���в���װ�ء��Է�����ϵͳӦ�Ƚ��м����Բ��ԡ�"
echo -e "#rpm �Cqa����鿴�汾��\n#RPM-ivh ***.RPM �����ϵͳ�򲹶���"

    Out_msg_end;
    return 0;
}

function Check_Linux_26(){
    Out_msg_head 26 "��������д������ε�NTP��������Ӧ������ϵͳʹ��NTP���񱣳�ʱ��ͬ����"

        echo -e "�ֶ����ã��ο����ò�����\n
#crontab -e 
����һ�У�30 8 * * * root /usr/sbin/ntpdate $ServerIP; /sbin/hwclock -w 
��$ServerIPΪNTP������IP��ַ,i.e:192.168.0.1��
�����crond�Ƿ������ã�#chkconfig --list|grep crond��service crond status��
��Ҫ���俪����#chkconfig crond on; service crond start;
���ntpd�������Ƿ��ѹرգ�#chkconfig --list|grep ntpd��service ntpd status;
��Ҫ����رգ�#chkconfig ntpd off;service ntpd stop"

    Out_msg_end;
    return 0;
}

function Check_Linux_27(){
    Out_msg_head 27 "NFS�������û�б�Ҫ����ҪֹͣNFS���������ҪNFS������Ҫ�����ܹ�����NFS�����IP��Χ��"
    echo -e "
ֹͣNFS����
Service nfs stop

�����ܹ�����NFS�����IP��Χ��
�༭�ļ���vi /etc/hosts.allow
����һ��: nfs: ������ʵ�IP    
    "

    Out_msg_end;
    return 0;
}

function Check_Linux_28(){
    Out_msg_head 28 "��ֹ��ջ�������";

        Limit_Conf_File=/etc/security/limits.conf
        Var=`ulimit -c`
            if [ $Var == 0 ] ; then
                echo "�Ѽӹ�"��
            else
                echo "δ����$Limit_Conf_File��core��Ϊ0�������޸�..."
                echo "* soft core 0" >>$Limit_Conf_File
                echo "* hard core 0" >>$Limit_Conf_File
                echo "���޸ġ�"
            fi

    Out_msg_end;
    return 0;
}

function Check_Linux_29(){
    Out_msg_head 29 "�г�ϵͳ����ʱ�Զ����صĽ��̺ͷ����б����ڴ��б����رա�";

    echo "�رղ�����ʹ�õķ���:��sendmail portmap cups named apache xfs vsftpd lpd linuxconf identd smb�ȷ���"
    echo "���ֶ�ִ��ServConf.sh�ű���"
    
    Out_msg_end;
    return 0;
}

function Check_Linux_30(){
    Out_msg_head 30 "���ӷ�������CPU��Ӳ�̡��ڴ桢�������Դ��";

    echo "ʹ�õ������������ϵͳ���м��"    

    Out_msg_end;
    return 0;
}

function Check_Linux_31(){
    Out_msg_head 31 "�г�����Ҫ������б�(���������ϵͳ����)�����ڴ��б�ķ�����رա�"

echo "����ϵͳӦ�����ѡ���ֹ���в���Ҫ�Ļ����������
time echo discard daytime chargen fs dtspc exec comsat talk finger uucp name xaudio netstat ufsd rexd systat sun-dr uuidgen krb5_prop"
    Out_msg_end;
    return 0;
}



#-------------------------------------------------------------------------------
#  main
#-------------------------------------------------------------------------------


BACKUP_SYS_CONF;

for i in `seq 1 31`
do
    Check_Linux_$i;
done

#ִ��Venus.sh�ű�
if [ -w ./Venus.sh ] ; then
  . ./Venus.sh 

  for i in `awk -F"[ (_]" '/function\ Venus/{print $4}' ./Venus.sh `
  do
    if [ $i -ne 38 ] && [ $i -ne 54 ]  ; then
      Venus_Linux_$i;
    else
      echo "Venus_Linux_$i���з��սϴ󣬲��޸�"
    fi      
  done
fi

echo "��ɳ�ʼ��������������ϵͳreboot"

exit 0;
