# -*- coding: utf-8 -*-
import iptc
import os

def add_iptables_rule(table, chain, protocol=None, src_ip=None, dst_ip=None, out_interface=None, dst_port=None, action=None, to_destination=None):
    """
    添加iptables规则
    :param table: iptables表
    :param chain: iptables链
    :param protocol: 协议
    :param src_ip: 源IP
    :param dst_ip: 目标IP
    :param out_interface: 出接口
    :param dst_port: 目标端口
    :param action: 动作
    :param to_destination: 目标地址和端口
    """
    # 创建iptables规则
    rule = iptc.Rule()
    if protocol is not None:
        rule.protocol = protocol
    if src_ip is not None:
        rule.src = src_ip
    if dst_ip is not None:
        rule.dst = dst_ip
    if out_interface is not None:
        rule.out_interface = out_interface
    if action is not None:
        rule.target = iptc.Target(rule, action)
    if protocol is not None and dst_port is not None:
        match = rule.create_match(protocol)
        match.dport = dst_port
    if action is not None and to_destination is not None:
        target = rule.create_target(action)
        target.to_destination = to_destination
    # 将规则添加到iptables链中
    chain = iptc.Chain(iptc.Table(table), chain)
    chain.insert_rule(rule)

# 添加端口转发规则
#add_iptables_rule("nat", "PREROUTING", protocol="tcp", dst_port="3222", action="DNAT", to_destination="192.168.122.2:22")

# 添加防火墙规则
#add_iptables_rule("filter", "FORWARD", protocol="tcp", src_ip="218.76.50.10", dst_ip="192.168.122.2", out_interface="virbr0", dst_port="22", action="ACCEPT")

def get_iptables_rule(table, chain, version):
    """
    获取iptables规则
    :param table: iptables表
    :param chain: iptables链
    :return: iptables规则列表
    """
    # 获取iptables表和链
    table = iptc.Table(table)
    chain = iptc.Chain(table, chain)
    # 获取iptables规则
    rules = []
    for rule in chain.rules:
        if rule.protocol == "tcp":
            r = {}
            if rule.protocol:
                r['protocol'] = rule.protocol
            if rule.src:
                r['src_ip'] = rule.src
            if rule.target and rule.target.name == 'DNAT' and rule.target.to_destination:
                r['to_destination'] = rule.target.to_destination
            if rule.dst:
                r['dst_ip'] = rule.dst
            if rule.in_interface:
                r['in_interface'] = rule.in_interface
            if rule.out_interface:
                r['out_interface'] = rule.out_interface
            if rule.target.name:
                r['action'] = rule.target.name
            if rule.matches:
                for match in rule.matches:
                    if match.name == "tcp":
                        r['dst_port'] = match.dport
                    elif match.name == "udp":
                        r['dst_port'] = match.dport
            rules.append(r)
    return rules

def delete_iptables_rule(table, chain, rule_spec):
    """
    删除指定的iptables规则
    :param table: iptables表
    :param chain: iptables链
    :param rule_spec: 要删除的iptables规则
    :return: None
    """
    if table == "nat" and chain == "PREROUTING":
        need_delete_rule = "iptables -t " + table + " -D " + chain + " " + rule_spec
    elif table == "filter" and chain == "FORWARD":
        need_delete_rule = "iptables -D " + chain + " " + rule_spec
    # 删除iptables规则
    os.system(need_delete_rule)
    os.system("systemctl restart flask")
    message = "规则已删除：{}".format(rule_spec)
    return message


# 获取filter表FORWARD链中的所有规则
#forward_rules = get_iptables_rule("filter", "FORWARD")
## 打印FORWARD规则
#for rule in forward_rules:
#    print(rule)
#
#nat_rules = get_iptables_rule("nat", "PREROUTING")
#for rule in nat_rules:
#    print(rule)
