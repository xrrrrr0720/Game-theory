import networkx as nx
import numpy as np
import pandas as pd
from scipy.optimize import linprog
import matplotlib.pyplot as plt


# 构建网络拓扑结构
def build_network_topology():
    G = nx.Graph()
    # 添加节点（服务器、主机、路由器等）
    G.add_nodes_from(['WebServer', 'FTPServer', 'MSSQLServer', 'MailServer', 'AttackerHost', 'Router'])
    # 设置节点属性（IP地址、操作系统、服务及版本、硬件配置等）
    node_attributes = {
        'WebServer': {'ip': '172.16.4.3', 'os': 'Windows server', 'services': {'IIS': '7.5'},
                      'hardware': 'Intel Xeon E5-2620 v4'},
        'FTPServer': {'ip': '172.16.4.4', 'os': 'Linux', 'services': {'vsftpd': '3.0.3'},
                      'hardware': 'AMD Opteron 6376'},
        'MSSQLServer': {'ip': '172.16.4.5', 'os': 'Windows server', 'services': {'MSSQL': '2017'},
                        'hardware': 'Intel Core i7-7700K'},
        'MailServer': {'ip': '172.16.4.6', 'os': 'Linux', 'services': {'Postfix': '3.3.0'},
                       'hardware': 'AMD Ryzen 5 3600'},
        'AttackerHost': {'ip': '202.119.80.2', 'os': 'Windows XP', 'hardware': 'Intel Core i5-10400F'},
        'Router': {'ip': '172.16.4.1', 'model': 'Cisco Router'}
    }
    nx.set_node_attributes(G, node_attributes)
    # 添加边并设置属性（如连接权限、带宽、延迟、丢包率等）
    G.add_edge('AttackerHost', 'Router', access='limited', bandwidth='100Mbps', delay='2ms', loss_rate='0.01')
    G.add_edge('Router', 'WebServer', access='public', bandwidth='1000Mbps', delay='1ms', loss_rate='0.005')
    G.add_edge('WebServer', 'FTPServer', access='private', bandwidth='100Mbps', delay='2ms', loss_rate='0.01')
    G.add_edge('WebServer', 'MSSQLServer', access='private', bandwidth='100Mbps', delay='2ms', loss_rate='0.01')
    G.add_edge('WebServer', 'MailServer', access='private', bandwidth='100Mbps', delay='2ms', loss_rate='0.01')
    return G


# 从模拟数据库获取漏洞信息（根据论文中的表格）
def get_vulnerabilities_from_database():
    vulnerabilities = {
        'CVE-2013-0003': {'server': 'WebServer', 'harm_index': 8.590, 'success_prob': 0.869,
                          'attack_type': 'Microsoft.NET Framework remote permission escalation',
                          'defense': 'Install Microsoft Bulletin MS13-004 security updates'},
        'CVE-2004-0330': {'server': 'FTPServer', 'harm_index': 6.249, 'success_prob': 0.625,
                          'attack_type': 'Serv-U FTP server MDTM order remote buffer overflow',
                          'defense': 'Update to Serv-U version 5.0.0.4 or higher'},
        'CVE-2010-3972': {'server': 'FTPServer', 'harm_index': 3.749, 'success_prob': 0.375,
                          'attack_type': 'IIS FTP server buffer overflow',
                          'defense': 'Install Microsoft IIS MS11-004 security updates'},
        'CVE-2002-0644': {'server': 'MSSQLServer', 'harm_index': 4.296, 'success_prob': 0.667,
                          'attack_type': 'Microsoft SQL Server Database buffer overflow',
                          'defense': 'Install Microsoft Bulletin MS02-038 security updates'},
        'CVE-2012-2527': {'server': 'MSSQLServer', 'harm_index': 1.315, 'success_prob': 0.131,
                          'attack_type': 'Microsoft Windows local permission escalation',
                          'defense': 'Install Microsoft Bulletin MS12-055 security updates'},
        'CVE-2001-0260': {'server': 'MailServer', 'harm_index': 6.441, 'success_prob': 0.999,
                          'attack_type': 'Lotus Domino mail server strategy buffer overflow',
                          'defense': 'Update to Lotus Domino Mail Server 5.0.6'}
    }
    return vulnerabilities


# 构建攻击策略集
def build_attack_strategies(vulnerabilities):
    attack_strategies = []
    for vuln_id, vuln_info in vulnerabilities.items():
        attack_strategy = {
            'name': vuln_info['attack_type'],
            'vulnerability': vuln_id,
            'server': vuln_info['server'],
            'harm_index': vuln_info['harm_index'],
            'success_prob': vuln_info['success_prob'],
            'preconditions': [],
            'steps': [],
            'consequences': [],
            'attack_type': vuln_info['attack_type']
        }
        # 根据论文中的攻击规则表模拟前置条件、步骤和后果
        if vuln_info['attack_type'] == 'Microsoft.NET Framework remote permission escalation':
            attack_strategy['preconditions'] = ['Attacker has network access to the target server.',
                                                'Target server has.NET Framework installed.',
                                                'The attacker has knowledge of the.NET Framework vulnerability.']
            attack_strategy['steps'] = ['Send a crafted request with malicious payload to the target server.',
                                        'Exploit the vulnerability in the.NET Framework to gain elevated permissions.',
                                        'Attempt to access sensitive resources on the server.']
            attack_strategy['consequences'] = ['Unauthorized access to server resources.',
                                               'Potential data theft or system compromise.',
                                               'Disruption of normal server operations.']
        elif vuln_info['attack_type'] == 'Serv-U FTP server MDTM order remote buffer overflow':
            attack_strategy['preconditions'] = ['Attacker has access to the FTP server.',
                                                'Server is running a vulnerable version of Serv-U.',
                                                'The attacker knows the buffer overflow vulnerability in Serv-U.']
            attack_strategy['steps'] = ['Send a malicious MDTM command with excessive data.',
                                        'Overflow the buffer in the Serv-U process.',
                                        'Execute arbitrary code with the elevated privileges.']
            attack_strategy['consequences'] = ['Gain control of the FTP server.', 'Disrupt FTP service operations.',
                                               'Potential data loss or corruption on the FTP server.']
        elif vuln_info['attack_type'] == 'IIS FTP server buffer overflow':
            attack_strategy['preconditions'] = ['Attacker has access to the IIS FTP server.',
                                                'The server is running a vulnerable version of IIS FTP service.',
                                                'The attacker has identified the buffer overflow vulnerability in IIS FTP.']
            attack_strategy['steps'] = [
                'Send a specially crafted request to the IIS FTP server to trigger the buffer overflow.',
                'Overwrite memory locations to gain control of the FTP server process.',
                'Use the gained access to perform malicious activities.']
            attack_strategy['consequences'] = ['Unauthorized access to the FTP server.',
                                               'Possible modification or deletion of FTP server files.',
                                               'Disruption of FTP service availability.']
        elif vuln_info['attack_type'] == 'Microsoft SQL Server Database buffer overflow':
            attack_strategy['preconditions'] = ['Attacker can communicate with the Microsoft SQL Server.',
                                                'The SQL Server is running a version with the buffer overflow vulnerability.',
                                                'The attacker has knowledge of the SQL Server vulnerability details.']
            attack_strategy['steps'] = [
                'Send a malicious SQL query designed to overflow a buffer in the SQL Server process.',
                'Exploit the buffer overflow to execute arbitrary code in the SQL Server context.',
                'Use the elevated privileges to access or manipulate the database.']
            attack_strategy['consequences'] = ['Unauthorized access to the SQL Server database.',
                                               'Potential data corruption or theft from the database.',
                                               'Disruption of normal database operations.']
        elif vuln_info['attack_type'] == 'Microsoft Windows local permission escalation':
            attack_strategy['preconditions'] = ['Attacker has a user account on the target Windows server.',
                                                'The server has a vulnerability that allows local permission escalation.',
                                                'The attacker has discovered the local permission escalation flaw.']
            attack_strategy['steps'] = [
                'Execute a malicious program or script that exploits the local permission escalation vulnerability.',
                'Gain higher privileges on the local system.',
                'Use the elevated permissions to access restricted system resources.']
            attack_strategy['consequences'] = ['Unauthorized access to system-level resources on the Windows server.',
                                               'Possible installation of backdoors or malware.',
                                               'Increased risk of further attacks on the system.']
        elif vuln_info['attack_type'] == 'Lotus Domino mail server strategy buffer overflow':
            attack_strategy['preconditions'] = ['Attacker can interact with the Lotus Domino mail server.',
                                                'The mail server is running a version vulnerable to buffer overflow in its strategy handling.',
                                                'The attacker is aware of the specific buffer overflow vulnerability.']
            attack_strategy['steps'] = [
                'Send a malicious request to the Lotus Domino mail server that triggers the buffer overflow.',
                'Overwrite memory to execute arbitrary code within the mail server process.',
                'Use the gained access to disrupt mail service or access user emails.']
            attack_strategy['consequences'] = ['Disruption of the Lotus Domino mail service.',
                                               'Potential unauthorized access to user emails.',
                                               'Possible data loss or corruption in the mail server.']
        attack_strategies.append(attack_strategy)
    return attack_strategies


# 构建防御策略集
def build_defense_strategies(vulnerabilities):
    defense_strategies = []
    for vuln_id in vulnerabilities.keys():
        defense_strategy = {
            'name': vulnerabilities[vuln_id]['defense'],
            'vulnerability': vuln_id,
            'defense_measures': []
        }
        # 根据论文中的漏洞信息模拟防御措施
        if vuln_id == 'CVE-2013-0003':
            defense_strategy['defense_measures'] = ['Download and install the security update from the official Microsoft website.',
                                                    'Verify the integrity of the downloaded update using digital signatures.',
                                                    'Apply the update and restart the relevant services (such as IIS and.NET Framework related services).',
                                                    'Conduct a post-update security scan to ensure the vulnerability is patched and no new issues have been introduced.',
                                                    'Monitor the system logs for any suspicious activities related to this vulnerability.']
        elif vuln_id == 'CVE-2004-0330':
            defense_strategy['defense_measures'] = ['Download the latest version of Serv-U from the official source.',
                                                    'Stop the running Serv-U service gracefully to avoid data loss.',
                                                    'Install the updated version and configure it properly according to the vendors guidelines.',
                                                    'Restart the FTP service and test its functionality to ensure normal operation.',
                                                    'Set up intrusion detection rules to monitor for any attempts to exploit this vulnerability in the future.']
        elif vuln_id == 'CVE-2010-3972':
            defense_strategy['defense_measures'] = ['Install the Microsoft IIS MS11-004 security update following the official instructions.',
                                                    'Verify that the update is successfully installed and IIS is running without errors.',
                                                    'Configure IIS security settings to restrict access and prevent buffer overflow attacks.',
                                                    'Regularly review and update IIS security configurations to stay protected against emerging threats.',
                                                    'Enable IIS logging and analyze the logs for any signs of malicious activity.']
        elif vuln_id == 'CVE-2002-0644':
            defense_strategy['defense_measures'] = ['Download and install the Microsoft Bulletin MS02-038 security update.',
                                                    'After installation, perform a system reboot if required.',
                                                    'Validate the integrity of the SQL Server database and its associated applications.',
                                                    'Implement strict access controls and user authentication mechanisms for the SQL Server.',
                                                    'Schedule regular database backups to mitigate the impact of potential attacks.']
        elif vuln_id == 'CVE-2012-2527':
            defense_strategy['defense_measures'] = ['Install the Microsoft Bulletin MS12-055 security update on the Windows server.',
                                                    'Verify the update installation and check for any system stability issues.',
                                                    'Review and update user account permissions and privileges to minimize the risk of local permission escalation.',
                                                    'Enable Windows security features such as User Account Control (UAC) and Windows Firewall.',
                                                    'Keep the Windows system updated with the latest patches and security fixes.']
        elif vuln_id == 'CVE-2001-0260':
            defense_strategy['defense_measures'] = ['Update the Lotus Domino Mail Server to version 5.0.6 or higher.',
                                                    'During the update process, ensure data integrity and backup important mailboxes.',
                                                    'Configure the mail servers security settings to prevent buffer overflow attacks.',
                                                    'Implement spam filtering and virus scanning to protect against malicious emails.',
                                                    'Regularly audit the mail servers access logs and user activities.']
        defense_strategies.append(defense_strategy)
    return defense_strategies


# 计算效用矩阵（根据论文中的公式）
def calculate_utility_matrix(attack_strategies, defense_strategies, network_topology):
    num_attack = len(attack_strategies)
    num_defense = len(defense_strategies)
    utility_matrix_attacker = np.zeros((num_attack, num_defense))
    utility_matrix_defender = np.zeros((num_attack, num_defense))

    for i, attack in enumerate(attack_strategies):
        for j, defense in enumerate(defense_strategies):
            if attack['vulnerability'] == defense['vulnerability']:
                # 更精确计算危害指数（考虑多种因素，根据论文中的定义）
                harm_index = calculate_harm_index(attack, network_topology)
                # 更准确计算成功概率（考虑多种因素，根据论文中的定义）
                success_prob = calculate_success_prob(attack, network_topology)
                cost_attack = 1 / success_prob
                cost_defense = 10 * success_prob
                utility_matrix_attacker[i][j] = harm_index - cost_attack
                utility_matrix_defender[i][j] = harm_index - cost_defense
            else:
                utility_matrix_attacker[i][j] = 0
                utility_matrix_defender[i][j] = 0

    return utility_matrix_attacker, utility_matrix_defender


def calculate_harm_index(attack, network_topology):
    # 考虑攻击对系统资源占用、数据泄露、业务影响等因素计算危害指数（根据论文中的定义）
    harm_index = attack['harm_index']
    # 根据网络拓扑和服务器属性进一步调整危害指数（根据论文中的定义）
    server = network_topology.nodes[attack['server']]
    if 'os' in server and server['os'].startswith('Windows'):
        harm_index *= 1.2
    if 'critical_services' in server and attack['attack_type'] in server['critical_services']:
        harm_index *= 1.5
    return harm_index


def calculate_success_prob(attack, network_topology):
    # 考虑攻击者技能水平、系统安全配置、网络监测防御有效性等因素计算成功概率（根据论文中的定义）
    success_prob = attack['success_prob']
    # 根据网络拓扑和服务器属性调整成功概率（根据论文中的定义）
    server = network_topology.nodes[attack['server']]
    if 'security_config' in server and server['security_config'] == 'high':
        success_prob *= 0.5
    if 'ids_enabled' in server and server['ids_enabled']:
        success_prob *= 0.8
    return success_prob


# 实现最优攻击防御决策算法（根据论文中的算法）
def optimal_attack_defense_decision(utility_matrix_attacker, utility_matrix_defender):
    num_attack, num_defense = utility_matrix_attacker.shape
    # 使用非线性规划求解混合策略纳什均衡（根据论文中的方法）
    c = -np.ravel(utility_matrix_attacker)
    Aub = np.ones((num_attack + num_defense, num_attack * num_defense))
    for i in range(num_attack):
        Aub[i, i * num_defense:(i + 1) * num_defense] = 1
    for i in range(num_defense):
        Aub[num_attack + i, i::num_defense] = 1
    bub = np.ones(num_attack + num_defense)
    bounds = [(0, 1)] * (num_attack * num_defense)
    result = linprog(c, A_ub=Aub, b_ub=bub, bounds=bounds)
    optimal_strategies = np.reshape(result.x, (num_attack, num_defense))
    optimal_attack_strategy = np.argmax(np.sum(optimal_strategies, axis=1))
    optimal_defense_strategy = np.argmax(np.sum(optimal_strategies, axis=0))
    return optimal_attack_strategy, optimal_defense_strategy


# 模拟攻击过程（根据论文中的攻击规则）
def simulate_attack(attack_strategy, network_topology):
    # 模拟攻击数据包生成和发送（根据论文中的攻击规则）
    attacker_host = network_topology.nodes['AttackerHost']
    target_server = network_topology.nodes[attack_strategy['server']]
    packet = generate_attack_packet(attacker_host, target_server, attack_strategy)
    send_attack_packet(packet)
    # 详细模拟漏洞利用过程（根据论文中的攻击规则）
    if is_vulnerability_exploitable(attack_strategy, network_topology):
        network_topology.nodes[attack_strategy['server']]['attacked'] = True
        print(f"Attacker successfully launched {attack_strategy['name']} on {attack_strategy['server']}")
    else:
        print(f"Attacker's attempt to launch {attack_strategy['name']} on {attack_strategy['server']} failed")


def generate_attack_packet(attacker_host, target_server, attack_strategy):
    # 根据攻击策略生成攻击数据包（根据论文中的攻击规则）
    packet = {
        'src_ip': attacker_host['ip'],
        'dst_ip': target_server['ip'],
        'payload': create_attack_payload(attack_strategy)
    }
    return packet


def create_attack_payload(attack_strategy):
    # 根据攻击类型创建攻击载荷（根据论文中的攻击规则）
    if attack_strategy['attack_type'] == 'Microsoft.NET Framework remote permission escalation':
        payload = b'\x01\x02\x03\x04'
    elif attack_strategy['attack_type'] == 'Serv-U FTP server MDTM order remote buffer overflow':
        payload = b'\x05\x06\x07\x08'
    # 其他攻击类型的载荷生成...
    return payload


def send_attack_packet(packet):
    # 发送攻击数据包（这里简化为打印信息，实际可能需要使用网络编程库发送数据包）
    print(f"Sending attack packet from {packet['src_ip']} to {packet['dst_ip']} with payload {packet['payload']}")


def is_vulnerability_exploitable(attack_strategy, network_topology):
    # 检查漏洞是否可利用（根据论文中的成功概率计算）
    success_prob = calculate_success_prob(attack_strategy, network_topology)
    return np.random.rand() < success_prob


# 模拟防御过程（根据论文中的防御策略）
def simulate_defense(defense_strategy, network_topology, vulnerabilities):
    protected_vulnerability = defense_strategy['vulnerability']
    for vuln_id, vuln_info in vulnerabilities.items():
        if vuln_id == protected_vulnerability:
            server = network_topology.nodes[vuln_info['server']]
            # 实施防御措施（如安装补丁、更新配置等，根据论文中的防御策略）
            install_patch(server, vuln_id)
            update_configuration(server, vuln_id)
            network_topology.nodes[vuln_info['server']]['protected'] = True
    print(f"Defender implemented {defense_strategy['name']} for {protected_vulnerability}")


def install_patch(server, vuln_id):
    # 模拟安装补丁操作（这里简化为打印信息）
    print(f"Installing patch for {vuln_id} on {server['ip']}")


def update_configuration(server, vuln_id):
    # 模拟更新配置操作（这里简化为打印信息）
    print(f"Updating configuration for {vuln_id} on {server['ip']}")


# 可视化效用矩阵
def visualize_utility_matrix(utility_matrix_attacker, utility_matrix_defender):
    fig, axs = plt.subplots(1, 2, figsize=(12, 5))
    axs[0].imshow(utility_matrix_attacker, cmap='hot', interpolation='nearest')
    axs[0].set_title('Attacker Utility Matrix')
    axs[0].set_xlabel('Defense Strategies')
    axs[0].set_ylabel('Attack Strategies')
    axs[1].imshow(utility_matrix_defender, cmap='hot', interpolation='nearest')
    axs[1].set_title('Defender Utility Matrix')
    axs[1].set_xlabel('Defense Strategies')
    axs[1].set_ylabel('Attack Strategies')
    plt.show()


# 主函数，执行复现流程
def main():
    network_topology = build_network_topology()
    vulnerabilities = get_vulnerabilities_from_database()
    attack_strategies = build_attack_strategies(vulnerabilities)
    defense_strategies = build_defense_strategies(vulnerabilities)
    utility_matrix_attacker, utility_matrix_defender = calculate_utility_matrix(attack_strategies, defense_strategies,
                                                                                network_topology)
    optimal_attack, optimal_defense = optimal_attack_defense_decision(utility_matrix_attacker, utility_matrix_defender)

    print(f"Optimal Attack Strategy: {attack_strategies[optimal_attack]['name']}")
    print(f"Optimal Defense Strategy: {defense_strategies[optimal_defense]['name']}")

    # 模拟攻击和防御过程
    simulate_attack(attack_strategies[optimal_attack], network_topology)
    simulate_defense(defense_strategies[optimal_defense], network_topology, vulnerabilities)

    # 可视化效用矩阵
    visualize_utility_matrix(utility_matrix_attacker, utility_matrix_defender)


if __name__ == "__main__":
    main()
