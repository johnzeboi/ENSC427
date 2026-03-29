#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/netanim-module.h"          // NetAnim
#include "ns3/mobility-module.h"          // Mobility for NetAnim node positioning

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("GamingDdosSimulation");

int main(int argc, char *argv[])
{
    uint32_t numClients       = 10;
    uint32_t numAttackers     = 10;
    double   simTime          = 60.0;
    bool     blacklistEnabled = true;

    double attackStartTime     = 5.0;
    double blacklistActivateAt = 15.0;

    CommandLine cmd;
    cmd.AddValue("numAttackers", "Number of DDoS attackers", numAttackers);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.Parse(argc, argv);

    // =========================================================
    // Create nodes
    // =========================================================
    NodeContainer server;
    server.Create(1);

    NodeContainer router;
    router.Create(1);

    NodeContainer clients;
    clients.Create(numClients);

    NodeContainer attackers;
    attackers.Create(numAttackers);

    // =========================================================
    // Internet stack
    // =========================================================
    InternetStackHelper stack;
    stack.Install(server);
    stack.Install(router);
    stack.Install(clients);
    stack.Install(attackers);

    // =========================================================
    // Link helpers
    // =========================================================
    PointToPointHelper accessLink;
    accessLink.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    accessLink.SetChannelAttribute("Delay",   StringValue("2ms"));

    PointToPointHelper bottleneck;
    bottleneck.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    bottleneck.SetChannelAttribute("Delay",   StringValue("10ms"));

    Ipv4AddressHelper address;

    std::vector<Ipv4InterfaceContainer> clientInterfaces;
    std::vector<Ipv4InterfaceContainer> attackerInterfaces;

    // =========================================================
    // Connect clients to router
    // =========================================================
    // Store bottleneck devices for PCAP capture later
    std::vector<NetDeviceContainer> clientDevices;

    for (uint32_t i = 0; i < numClients; i++)
    {
        NodeContainer pair(clients.Get(i), router.Get(0));
        NetDeviceContainer devices = accessLink.Install(pair);
        clientDevices.push_back(devices);

        std::ostringstream subnet;
        subnet << "10.1." << (i + 1) << ".0";
        address.SetBase(subnet.str().c_str(), "255.255.255.0");
        clientInterfaces.push_back(address.Assign(devices));
    }

    // =========================================================
    // Connect attackers to router
    // =========================================================
    std::vector<NetDeviceContainer> attackerDevices;

    for (uint32_t i = 0; i < numAttackers; i++)
    {
        NodeContainer pair(attackers.Get(i), router.Get(0));
        NetDeviceContainer devices = accessLink.Install(pair);
        attackerDevices.push_back(devices);

        std::ostringstream subnet;
        subnet << "10.2." << (i + 1) << ".0";
        address.SetBase(subnet.str().c_str(), "255.255.255.0");
        attackerInterfaces.push_back(address.Assign(devices));
    }

    // =========================================================
    // Connect router to server (bottleneck)
    // =========================================================
    NodeContainer routerServer(router.Get(0), server.Get(0));
    NetDeviceContainer bottleneckDevices = bottleneck.Install(routerServer);

    address.SetBase("10.3.0.0", "255.255.255.0");
    Ipv4InterfaceContainer serverInterface = address.Assign(bottleneckDevices);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    Ipv4Address serverAddress = serverInterface.GetAddress(1);

    std::vector<Ipv4Address> clientAddresses;
    for (uint32_t i = 0; i < numClients; i++)
        clientAddresses.push_back(clientInterfaces[i].GetAddress(0));

    // =========================================================
    // NetAnim — set node positions
    // Layout: clients on the left, router in the middle,
    //         server on the right, attackers below router.
    // =========================================================

    // Mobility helper used to assign fixed positions for NetAnim
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    // Install mobility on all nodes
    mobility.Install(server);
    mobility.Install(router);
    mobility.Install(clients);
    if (numAttackers > 0)
        mobility.Install(attackers);

    // Server — far right
    AnimationInterface::SetConstantPosition(server.Get(0), 90.0, 50.0);

    // Router — centre
    AnimationInterface::SetConstantPosition(router.Get(0), 50.0, 50.0);

    // Clients — spread vertically on the left
    for (uint32_t i = 0; i < numClients; i++)
    {
        double y = 10.0 + i * (80.0 / std::max(numClients - 1, (uint32_t)1));
        AnimationInterface::SetConstantPosition(clients.Get(i), 10.0, y);
    }

    // Attackers — spread below router
    for (uint32_t i = 0; i < numAttackers; i++)
    {
        double x = 30.0 + i * (40.0 / std::max(numAttackers - 1, (uint32_t)1));
        AnimationInterface::SetConstantPosition(attackers.Get(i), x, 85.0);
    }

    // =========================================================
    // Gaming server
    // =========================================================
    uint16_t port = 4000;
    UdpServerHelper gameServer(port);
    ApplicationContainer serverApp = gameServer.Install(server.Get(0));
    serverApp.Start(Seconds(1.0));
    serverApp.Stop(Seconds(simTime));

    // =========================================================
    // Legitimate game clients
    // =========================================================
    for (uint32_t i = 0; i < numClients; i++)
    {
        UdpClientHelper gameClient(serverAddress, port);
        gameClient.SetAttribute("MaxPackets", UintegerValue(1000000));
        gameClient.SetAttribute("Interval",   TimeValue(MilliSeconds(20)));
        gameClient.SetAttribute("PacketSize", UintegerValue(128));

        ApplicationContainer clientApp = gameClient.Install(clients.Get(i));
        clientApp.Start(Seconds(2.0));
        clientApp.Stop(Seconds(simTime));
    }

    // =========================================================
    // DDoS attackers
    // =========================================================
    for (uint32_t i = 0; i < numAttackers; i++)
    {
        OnOffHelper attacker("ns3::UdpSocketFactory",
                             Address(InetSocketAddress(serverAddress, port)));

        attacker.SetAttribute("DataRate",   StringValue("50Mbps"));
        attacker.SetAttribute("PacketSize", UintegerValue(1024));
        attacker.SetAttribute("OnTime",
            StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        attacker.SetAttribute("OffTime",
            StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        ApplicationContainer attackApp = attacker.Install(attackers.Get(i));
        attackApp.Start(Seconds(attackStartTime));

        if (blacklistEnabled)
            attackApp.Stop(Seconds(blacklistActivateAt));
        else
            attackApp.Stop(Seconds(simTime));
    }

    if (blacklistEnabled)
    {
        std::cout << "[Mitigation] Blacklist active: attackers flood from "
                  << attackStartTime << "s, blocked at "
                  << blacklistActivateAt << "s ("
                  << (blacklistActivateAt - attackStartTime)
                  << "s detection window).\n";
    }

    // =========================================================
    // PCAP capture (Wireshark)
    // Captures on the bottleneck link (router<->server) —
    // the most useful point to observe congestion.
    // Also captures on client 0 and attacker 0 (if present)
    // for comparison.
    // Output files will be named:
    //   ddos-bottleneck-*.pcap
    //   ddos-client0-*.pcap
    //   ddos-attacker0-*.pcap
    // Open these directly in Wireshark.
    // =========================================================
    bottleneck.EnablePcap("ddos-bottleneck", bottleneckDevices, true);
    accessLink.EnablePcap("ddos-client0",    clientDevices[0],  true);

    if (numAttackers > 0)
        accessLink.EnablePcap("ddos-attacker0", attackerDevices[0], true);

    // =========================================================
    // NetAnim output
    // Open ddos-animation.xml in NetAnim after simulation.
    // =========================================================
    AnimationInterface anim("ddos-animation.xml");

    // Label nodes in NetAnim
    anim.UpdateNodeDescription(server.Get(0), "Server");
    anim.UpdateNodeDescription(router.Get(0), "Router");
    for (uint32_t i = 0; i < numClients; i++)
    {
        std::ostringstream label;
        label << "Client " << i;
        anim.UpdateNodeDescription(clients.Get(i), label.str());
    }
    for (uint32_t i = 0; i < numAttackers; i++)
    {
        std::ostringstream label;
        label << "Attacker " << i;
        anim.UpdateNodeDescription(attackers.Get(i), label.str());
    }

    // Colour nodes: clients = green, attackers = red, server = blue, router = grey
    for (uint32_t i = 0; i < numClients; i++)
        anim.UpdateNodeColor(clients.Get(i), 0, 255, 0);
    for (uint32_t i = 0; i < numAttackers; i++)
        anim.UpdateNodeColor(attackers.Get(i), 255, 0, 0);
    anim.UpdateNodeColor(server.Get(0), 0, 0, 255);
    anim.UpdateNodeColor(router.Get(0), 128, 128, 128);

    // =========================================================
    // Flow monitor
    // =========================================================
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // =========================================================
    // QoS analysis
    // =========================================================
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

    std::cout << "\n=== Gaming QoS Results (Legitimate Clients Only) ===\n";
    std::cout << "Scenario: " << (blacklistEnabled ? "Attack + Blacklist Mitigation" : "Attack No Mitigation") << "\n";
    std::cout << "Simulation Time: " << simTime << "s (Attack starts at " << attackStartTime << "s)\n\n";

    if (stats.empty())
    {
        std::cout << "ERROR: No flows detected! Check network configuration.\n";
        Simulator::Destroy();
        return 1;
    }

    uint32_t legitimateFlows = 0;
    double   totalThroughput = 0;
    double   totalPacketLoss = 0;
    double   totalDelay      = 0;
    double   totalJitter     = 0;

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
            continue;

        legitimateFlows++;

        double flowDuration =
            (flow.second.timeLastRxPacket - flow.second.timeFirstRxPacket).GetSeconds();

        if (flowDuration <= 0)
            flowDuration = simTime - 2.0;

        double throughput = (flow.second.rxBytes * 8.0) / (flowDuration * 1000000.0);

        double packetLoss = 0;
        if (flow.second.txPackets > 0)
            packetLoss = (double)flow.second.lostPackets / flow.second.txPackets;

        double avgDelay = 0;
        if (flow.second.rxPackets > 0)
            avgDelay = flow.second.delaySum.GetSeconds() / flow.second.rxPackets;

        double avgJitter = 0;
        if (flow.second.rxPackets > 1)
            avgJitter = flow.second.jitterSum.GetSeconds() / (flow.second.rxPackets - 1);

        std::cout << "Flow ID: " << flow.first << "\n";
        std::cout << "  Source: "      << t.sourceAddress << " -> " << t.destinationAddress << "\n";
        std::cout << "  Throughput: "  << throughput         << " Mbps\n";
        std::cout << "  Avg Delay: "   << avgDelay   * 1000  << " ms\n";
        std::cout << "  Avg Jitter: "  << avgJitter  * 1000  << " ms\n";
        std::cout << "  Packet Loss: " << (packetLoss * 100) << "%\n";
        std::cout << "  Tx Packets: "  << flow.second.txPackets
                  << ", Rx Packets: "  << flow.second.rxPackets
                  << ", Lost: "        << flow.second.lostPackets << "\n\n";

        totalThroughput += throughput;
        totalPacketLoss += packetLoss;
        totalDelay      += avgDelay;
        totalJitter     += avgJitter;
    }

    // =========================================================
    // Print aggregate stats
    // =========================================================
    if (legitimateFlows > 0)
    {
        std::cout << "=== Aggregate Metrics (Average across " << legitimateFlows << " clients) ===\n";
        std::cout << "Avg Throughput: "  << (totalThroughput / legitimateFlows)        << " Mbps\n";
        std::cout << "Avg Delay: "       << (totalDelay      / legitimateFlows * 1000) << " ms\n";
        std::cout << "Avg Jitter: "      << (totalJitter     / legitimateFlows * 1000) << " ms\n";
        std::cout << "Avg Packet Loss: " << (totalPacketLoss / legitimateFlows * 100)  << "%\n";
    }
    else
    {
        std::cout << "ERROR: No legitimate client flows found!\n";
    }

    Simulator::Destroy();
    return 0;
}