# -*- coding: utf-8 -*-
import iptc
from flask import Flask, request, jsonify, render_template
from iptables import get_iptables_rule,add_iptables_rule,delete_iptables_rule
app = Flask(__name__)

# flask配置
app.config['TEMPLATES_AUTO_RELOAD'] = False
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_MIMETYPE'] = 'application/json'

# 获取FORWARD规则
@app.route('/iptables/get_forward_rules', methods=['GET'])
def get_forward_rules():
    # 获取filter表FORWARD链中的所有规则
    forward_rules = get_iptables_rule("filter", "FORWARD")
    json_forward_rules = jsonify({'forward_rules': forward_rules})
    return json_forward_rules

# 获取NAT规则
@app.route('/iptables/get_nat_rules', methods=['GET'])
def get_nat_rules():
    # 获取nat表PREROUTING链中的所有规则
    nat_rules = get_iptables_rule("nat", "PREROUTING")
    json_nat_rules = jsonify({'nat_rules': nat_rules})
    return json_nat_rules

# 获取INPUT规则
@app.route('/iptables/get_input_rules', methods=['GET'])
def get_input_rules():
    # 获取nat表PREROUTING链中的所有规则
    input_rules = get_iptables_rule("filter", "IN_public_allow")
    json_input_rules = jsonify({'input_rules': input_rules})
    return json_input_rules

# 删除iptables规则
@app.route('/iptables/delete_rule', methods=['POST'])
def delete_rule():
    data = request.get_json()
#    key = data.get('key') # 获取请求中的key参数
#    if key != 'mUha38KvGGCkDCRAyFMR':
#        return jsonify({'message': '无效的校验参数！'}), 406
    table = data.get('table')
    chain = data.get('chain')
    rule_spec = data.get('rule')
    if not rule_spec:
        return jsonify({'message': '规则不能为空！'}), 400
    delete_iptables_rule(table, chain, rule_spec)
    return jsonify({'message': '规则删除成功！'})

# 添加iptables规则
@app.route('/iptables/add_rule', methods=['POST'])
def add_rule():
    # 从请求中获取规则参数
    data = request.json
    table = data['table']
    chain = data['chain']
    protocol = data.get('protocol')
    src_ip = data.get('src_ip')
    dst_ip = data.get('dst_ip')
    out_interface = data.get('out_interface')
    dst_port = data.get('dst_port')
    action = data.get('action')
    to_destination = data.get('to_destination')
    if table == "nat":
        add_iptables_rule(table, chain, protocol=protocol, dst_port=dst_port, action=action, to_destination=to_destination)
    elif table == "filter":
        add_iptables_rule(table, chain, protocol=protocol, src_ip=src_ip, dst_ip=dst_ip, out_interface=out_interface, dst_port=dst_port, action=action)
    message = '规则添加成功！'
    return jsonify({'message': message}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
