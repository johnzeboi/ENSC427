#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("GamingDdosSimulation");

int main(int argc, char *argv[])
{
    uint32_t numClients = 5;
    uint32_t numAttackers = 10;
    double simTime = 60.0;  // adjust for quicker/accurate results

    CommandLine cmd;
    cmd.AddValue("numAttackers", "Number of DDoS attackers", numAttackers);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.Parse(argc, argv);

    //create nodes
	//
    NodeContainer server;
    server.Create(1);

    NodeContainer router;
    router.Create(1);

    NodeContainer clients;
    clients.Create(numClients);

    NodeContainer attackers;
    attackers.Create(numAttackers);

	//internet stack
	//
    InternetStackHelper stack;
    stack.Install(server);
    stack.Install(router);
    stack.Install(clients);
    stack.Install(attackers);

	//link helpers
	//
    PointToPointHelper accessLink;
    accessLink.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    accessLink.SetChannelAttribute("Delay", StringValue("2ms"));

    PointToPointHelper bottleneck;
    bottleneck.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    bottleneck.SetChannelAttribute("Delay", StringValue("10ms"));

    Ipv4AddressHelper address;

    std::vector<Ipv4InterfaceContainer> clientInterfaces;
    std::vector<Ipv4InterfaceContainer> attackerInterfaces;

	//connect clients to router
	//
    for (uint32_t i = 0; i < numClients; i++)
    {
        NodeContainer pair(clients.Get(i), router.Get(0));
        NetDeviceContainer devices = accessLink.Install(pair);

        std::ostringstream subnet;
        subnet << "10.1." << i + 1 << ".0";
        address.SetBase(subnet.str().c_str(), "255.255.255.0");

        clientInterfaces.push_back(address.Assign(devices));
    }

	//connect attackers to router
	//
    for (uint32_t i = 0; i < numAttackers; i++)
    {
        NodeContainer pair(attackers.Get(i), router.Get(0));
        NetDeviceContainer devices = accessLink.Install(pair);

        std::ostringstream subnet;
        subnet << "10.2." << i + 1 << ".0";
        address.SetBase(subnet.str().c_str(), "255.255.255.0");

        attackerInterfaces.push_back(address.Assign(devices));
    }

	//connect router to server (bottleneck point)
	//
    NodeContainer routerServer(router.Get(0), server.Get(0));
    NetDeviceContainer bottleneckDevices = bottleneck.Install(routerServer);

    address.SetBase("10.3.0.0", "255.255.255.0");
    Ipv4InterfaceContainer serverInterface = address.Assign(bottleneckDevices);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    Ipv4Address serverAddress = serverInterface.GetAddress(1);
    
    std::vector<Ipv4Address> clientAddresses;
    for (uint32_t i = 0; i < numClients; i++)
    {
        clientAddresses.push_back(clientInterfaces[i].GetAddress(0));
    }

	//install gaming server
	//
    uint16_t port = 4000;
    UdpServerHelper gameServer(port);
    ApplicationContainer serverApp = gameServer.Install(server.Get(0));
    serverApp.Start(Seconds(1.0));
    serverApp.Stop(Seconds(simTime));

	//install legitimate game clients
	//
    for (uint32_t i = 0; i < numClients; i++)
    {
        UdpClientHelper gameClient(serverAddress, port);
        gameClient.SetAttribute("MaxPackets", UintegerValue(1000000));
        gameClient.SetAttribute("Interval", TimeValue(MilliSeconds(20)));
        gameClient.SetAttribute("PacketSize", UintegerValue(128));

        ApplicationContainer clientApp = gameClient.Install(clients.Get(i));
        clientApp.Start(Seconds(2.0));
        clientApp.Stop(Seconds(simTime));
    }

	//install DDoS attackers
	//
    for (uint32_t i = 0; i < numAttackers; i++)
    {
        OnOffHelper attacker("ns3::UdpSocketFactory",
                             Address(InetSocketAddress(serverAddress, port)));

        attacker.SetAttribute("DataRate", StringValue("50Mbps"));
        attacker.SetAttribute("PacketSize", UintegerValue(1024));
        attacker.SetAttribute("OnTime",
            StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        attacker.SetAttribute("OffTime",
            StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer attackApp = attacker.Install(attackers.Get(i));
        attackApp.Start(Seconds(5.0));
        attackApp.Stop(Seconds(simTime));
    }

	//flow monitor
	//
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

	//QoS analysis
	//
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

    std::cout << "\n=== Gaming QoS Results (Legitimate Clients Only) ===\n";
    std::cout << "Simulation Time: " << simTime << "s (Attack: 5s-" << simTime << "s)\n\n";

    if (stats.empty())
    {
        std::cout << "ERROR: No flows detected! Check network configuration.\n";
        Simulator::Destroy();
        return 1;
    }

    uint32_t legitimateFlows = 0;
    double totalThroughput = 0;
    double totalPacketLoss = 0;
    double totalDelay = 0;
    double totalJitter = 0;

    for (auto const &flow : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);

        bool isLegitimate = false;
        for (const auto& clientAddr : clientAddresses)
        {
            if (t.sourceAddress == clientAddr && t.destinationAddress == serverAddress)
            {
                isLegitimate = true;
                break;
            }
        }

        if (!isLegitimate)
        {
            continue;
        }

        legitimateFlows++;

        double flowDuration = 
            (flow.second.timeLastRxPacket - flow.second.timeFirstRxPacket).GetSeconds();
        
        if (flowDuration <= 0)
        {
            flowDuration = simTime - 2.0;  //client starts at 2s
        }

        double throughput = (flow.second.rxBytes * 8.0) / (flowDuration * 1000000.0);

        double packetLoss = 0;
        if (flow.second.txPackets > 0)
        {
            packetLoss = (double)flow.second.lostPackets / flow.second.txPackets;
        }

        double avgDelay = 0;
        if (flow.second.rxPackets > 0)
        {
            avgDelay = flow.second.delaySum.GetSeconds() / flow.second.rxPackets;
        }

        double avgJitter = 0;
        if (flow.second.rxPackets > 1)
        {
            avgJitter = flow.second.jitterSum.GetSeconds() / (flow.second.rxPackets - 1);
        }

        std::cout << "Flow ID: " << flow.first << "\n";
        std::cout << "  Source: " << t.sourceAddress << " -> " << t.destinationAddress << "\n";
        std::cout << "  Throughput: " << throughput << " Mbps\n";
        std::cout << "  Avg Delay: " << avgDelay * 1000 << " ms\n";
        std::cout << "  Avg Jitter: " << avgJitter * 1000 << " ms\n";
        std::cout << "  Packet Loss: " << (packetLoss * 100) << "%\n";
        std::cout << "  Tx Packets: " << flow.second.txPackets 
                  << ", Rx Packets: " << flow.second.rxPackets 
                  << ", Lost: " << flow.second.lostPackets << "\n\n";

        totalThroughput += throughput;
        totalPacketLoss += packetLoss;
        totalDelay += avgDelay;
        totalJitter += avgJitter;
    }

	//print stats
    if (legitimateFlows > 0)
    {
        std::cout << "=== Aggregate Metrics (Average across " << legitimateFlows << " clients) ===\n";
        std::cout << "Avg Throughput: " << (totalThroughput / legitimateFlows) << " Mbps\n";
        std::cout << "Avg Delay: " << (totalDelay / legitimateFlows * 1000) << " ms\n";
        std::cout << "Avg Jitter: " << (totalJitter / legitimateFlows * 1000) << " ms\n";
        std::cout << "Avg Packet Loss: " << (totalPacketLoss / legitimateFlows * 100) << "%\n";
    }
    else
    {
        std::cout << "ERROR: No legitimate client flows found!\n";
    }

    Simulator::Destroy();
    return 0;
}