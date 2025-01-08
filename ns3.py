import ns.network as network
import ns.internet as internet
import ns.applications as applications
import ns.core as core

def create_network_topology():
    """
    创建网络拓扑，包括攻击者、Web服务器、FTP服务器、邮件服务器和SQL服务器。
    """
    # 创建节点
    attacker = network.Node()
    web_server = network.Node()
    ftp_server = network.Node()
    mail_server = network.Node()
    sql_server = network.Node()

    # 创建节点容器
    nodes = network.NodeContainer()
    nodes.Add(attacker)
    nodes.Add(web_server)
    nodes.Add(ftp_server)
    nodes.Add(mail_server)
    nodes.Add(sql_server)

    # 安装网络协议栈
    stack = internet.InternetStackHelper()
    stack.Install(nodes)

    # 创建点对点链路
    link_helper = network.PointToPointHelper()
    link_helper.SetDeviceAttribute("DataRate", core.StringValue("10Mbps"))
    link_helper.SetChannelAttribute("Delay", core.StringValue("2ms"))

    attacker_to_web = link_helper.Install(attacker, web_server)
    web_to_ftp = link_helper.Install(web_server, ftp_server)
    web_to_mail = link_helper.Install(web_server, mail_server)
    web_to_sql = link_helper.Install(web_server, sql_server)

    # 分配IP地址
    address_helper = internet.Ipv4AddressHelper()
    address_helper.SetBase(core.Ipv4Address("10.1.1.0"), core.Ipv4Mask("255.255.255.0"))
    attacker_to_web_interfaces = address_helper.Assign(attacker_to_web)

    address_helper.SetBase(core.Ipv4Address("10.1.2.0"), core.Ipv4Mask("255.255.255.0"))
    web_to_ftp_interfaces = address_helper.Assign(web_to_ftp)

    address_helper.SetBase(core.Ipv4Address("10.1.3.0"), core.Ipv4Mask("255.255.255.0"))
    web_to_mail_interfaces = address_helper.Assign(web_to_mail)

    address_helper.SetBase(core.Ipv4Address("10.1.4.0"), core.Ipv4Mask("255.255.255.0"))
    web_to_sql_interfaces = address_helper.Assign(web_to_sql)

    return nodes, attacker, web_server, ftp_server, mail_server, sql_server

def simulate_attack(attacker, target, vulnerability, attack_start, attack_duration):
    """
    模拟对目标节点的漏洞攻击。
    """
    print(f"Simulating attack on {target.GetId()} using {vulnerability}...")

    # 设置攻击流量
    attack_app = applications.OnOffHelper("ns3::TcpSocketFactory",
                                          internet.InetSocketAddress(target.GetObject(internet.Ipv4).GetAddress(1, 0).GetLocal(), 80))
    attack_app.SetAttribute("OnTime", core.StringValue("ns3::ConstantRandomVariable[Constant=1]"))
    attack_app.SetAttribute("OffTime", core.StringValue("ns3::ConstantRandomVariable[Constant=0]"))
    attack_app.SetAttribute("DataRate", core.StringValue("1Mbps"))
    attack_app.SetAttribute("PacketSize", core.UintegerValue(1024))

    # 安装攻击应用程序
    app = attack_app.Install(attacker)
    app.Start(core.Seconds(attack_start))
    app.Stop(core.Seconds(attack_start + attack_duration))

def setup_vulnerability_simulation(attacker, web_server, ftp_server, mail_server, sql_server):
    """
    设置基于图3和表1的漏洞攻击模拟。
    """
    # CVE-2013-0003: 攻击Web服务器，权限提升到Root
    simulate_attack(attacker, web_server, "CVE-2013-0003", 1.0, 5.0)

    # CVE-2004-0330: 攻击FTP服务器
    simulate_attack(web_server, ftp_server, "CVE-2004-0330", 6.0, 5.0)

    # CVE-2010-3972: 攻击FTP服务器
    simulate_attack(web_server, ftp_server, "CVE-2010-3972", 12.0, 5.0)

    # CVE-2002-0644: 攻击SQL服务器
    simulate_attack(web_server, sql_server, "CVE-2002-0644", 18.0, 5.0)

    # CVE-2012-2527: 攻击SQL服务器
    simulate_attack(web_server, sql_server, "CVE-2012-2527", 24.0, 5.0)

    # CVE-2001-0260: 攻击邮件服务器
    simulate_attack(web_server, mail_server, "CVE-2001-0260", 30.0, 5.0)

def main():
    """
    主函数：设置网络拓扑并运行模拟。
    """
    core.LogComponentEnable("AttackSimulation", core.LOG_LEVEL_INFO)

    # 创建网络拓扑
    nodes, attacker, web_server, ftp_server, mail_server, sql_server = create_network_topology()

    # 设置攻击模拟
    setup_vulnerability_simulation(attacker, web_server, ftp_server, mail_server, sql_server)

    # 运行模拟
    core.Simulator.Run()
    core.Simulator.Destroy()

if __name__ == "__main__":
    main()
