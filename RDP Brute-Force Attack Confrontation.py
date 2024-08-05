# coding: utf-8
import os
import re
import wmi
import sys
import json
import ipaddress
from time import sleep
from datetime import datetime, timedelta
from collections import Counter
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkvpc.v3.region.vpc_region import VpcRegion
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkvpc.v3 import *

# The AK and SK used for authentication are hard-coded or stored in plaintext, which has great security risks. It is recommended that the AK and SK be stored in ciphertext in configuration files or environment variables and decrypted during use to ensure security.
# In this example, AK and SK are stored in environment variables for authentication. Before running this example, set environment variables CLOUD_SDK_AK and CLOUD_SDK_SK in the local environment
configurationFile=open('configuration.json', 'r', encoding='utf-8')
configuration = json.load(configurationFile)
configurationFile.close()
aboutHuaweiCloud=configuration["Huawei cloud"]
ak = aboutHuaweiCloud["AK"]
sk = aboutHuaweiCloud["SK"]
vpsid=aboutHuaweiCloud["VPS ID"]
region=aboutHuaweiCloud["region"]
detetionInterval=configuration["DetectionInterval"]
detetionTimePeriod=configuration["DetectionTimePeriod"]
IPTryTime=configuration["IPTryTimes"]
logPath="./record/"
lastTime=datetime.now().date()
wmiIns = wmi.WMI()

def is_valid_ip(ip_str):
    try:
        # 尝试将字符串转换为 IPv4 或 IPv6 地址
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        # 如果转换失败，则不是有效的 IP 地址
        return False

def addBlockIP(blockIP):
    credentials = BasicCredentials(ak, sk)
    client = VpcClient.new_builder() \
        .with_credentials(credentials) \
        .with_region(VpcRegion.value_of(region)) \
        .build()
    try:
        request = CreateSecurityGroupRuleRequest()
        securityGroupRulebody = CreateSecurityGroupRuleOption(
            security_group_id=vpsid,
            description=f"脚本自动添加-RDP攻击拦截/Script auto-add-RDP attack blocking {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            direction="ingress",
            remote_ip_prefix=blockIP,
            action="deny",
            priority="1"
        )
        request.body = CreateSecurityGroupRuleRequestBody(
            security_group_rule=securityGroupRulebody
        )
        response = client.create_security_group_rule(request)
        print("封禁IP："+blockIP)
        print(response)
        file_path = os.path.join(logPath, f"{datetime.now().strftime('%Y-%m-%d')}.log")
        with open(file_path, 'a', encoding='utf-8') as file:
            file.write(blockIP + '\n')
        print(f'IP已追加到 {file_path}')
    except exceptions.ClientRequestException as e:
        print(e.status_code)
        print(e.request_id)
        print(e.error_code)
        print(e.error_msg)
        if 'Security group rule already exists.' in e.error_msg:
            file_path = os.path.join(logPath, f"{datetime.now().strftime('%Y-%m-%d')}.log")
            with open(file_path, 'a', encoding='utf-8') as file:
                file.write(blockIP + '\n')
            print(f'IP规则被提前追加，已记录到 {file_path}')
def getSecurityGroupRules():
    credentials = BasicCredentials(ak, sk)

    client = VpcClient.new_builder() \
        .with_credentials(credentials) \
        .with_region(VpcRegion.value_of("cn-north-4")) \
        .build()
    try:
        request = ShowSecurityGroupRequest()
        request.security_group_id = vpsid
        return client.show_security_group(request)
    except exceptions.ClientRequestException as e:
        print('获取安全组规则失败')
        print(e.status_code)
        print(e.request_id)
        print(e.error_code)
        print(e.error_msg)

def getBlockIPRulesID(blockIP):
    security_group_rules=getSecurityGroupRules().security_group.security_group_rules
    for security_group_rule in security_group_rules:
        if security_group_rule.remote_ip_prefix==blockIP+'/32':
            return security_group_rule.id
    print("没有找到该IP规则")
    return None
def removeBlockIP(blockIP):
    rule_id=getBlockIPRulesID(blockIP)
    if rule_id!=None:
        credentials = BasicCredentials(ak, sk)
        client = VpcClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(VpcRegion.value_of("cn-north-4")) \
            .build()
        try:
            request = DeleteSecurityGroupRuleRequest()
            request.security_group_rule_id = rule_id
            response = client.delete_security_group_rule(request)
            print(f'删除锁定IP({blockIP})成功！')
            print(response)
        except exceptions.ClientRequestException as e:
            print(e.status_code)
            print(e.request_id)
            print(e.error_code)
            print(e.error_msg)

def BlockedIPList():
    # 日期格式的正则表达式
    date_pattern = re.compile(r'\d{4}-\d{2}-\d{2}\.log$')
    content_list = []
    for filename in os.listdir(logPath):
        # 检查文件名是否符合日期格式
        if date_pattern.match(filename):
            file_path = os.path.join(logPath, filename)
            with open(file_path, 'r', encoding='utf-8') as file:
                for line in file:
                    content_list.append(line.strip())  # 去除行末的换行符并添加到列表中
    return content_list
def isIPBlocked(IP):
    return IP in BlockedIPList()
def detect():
    # 获取指定时间段前的日志
    start_time = datetime.now() - timedelta(minutes=detetionTimePeriod)
    start_time_str = start_time.strftime('%Y%m%d%H%M%S.000000-000')

    # 查询安全日志中事件ID为4625的所有条目
    query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile = 'Security' AND EventCode = '4625' AND TimeGenerated >= '{}'".format(start_time_str)
    try:
        events = wmiIns.query(query)
    except wmi.x_wmi as e:
        print(f"WMI query error: {e.com_error}")
        events = []

    ip_list = []
    for event in events:
        if is_valid_ip(event.InsertionStrings[19]):
            ip_list.append(event.InsertionStrings[19])
    element_count = Counter(ip_list)
    attackList = {key: value for key, value in element_count.items() if value > IPTryTime}
    blockedIPList=BlockedIPList()
    hasNewBlockedIP=False
    for item, count in attackList.items():
        if item not in blockedIPList:
            hasNewBlockedIP=True
            print(f"{item}: {count}")
            addBlockIP(item)
    if hasNewBlockedIP:
        print('')

def RemoveExpiredBannedIPs():
    global lastTime
    if datetime.now().date() > lastTime:
        if os.path.exists(os.path.join(logPath, f"{datetime.now().strftime('%Y-%m-%d')}.log")):
            logFile=open(os.path.join(logPath, f"{datetime.now().strftime('%Y-%m-%d')}.log"), 'r')
            for line in logFile:
                line=line.strip()
                removeBlockIP(line.strip()) if is_valid_ip(line) else print('Invalid IP'+line)
                print('安全组移除IP: '+line)
        else:
            print(f"No log {datetime.now().strftime('%Y-%m-%d')}.log file found")
        lastTime=datetime.now().date()
        print('')

if __name__ == "__main__":
    print('RDP爆破防御启动...')
    print('')
    loopTimes=1
    while True:
        detect()
        RemoveExpiredBannedIPs()
        sys.stdout.write(f'\r第{loopTimes}次循环完成')
        sys.stdout.flush()
        loopTimes+=1
        sleep(detetionInterval*60)
