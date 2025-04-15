package com.github.lucasskywalker64;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket.ArpHeader;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

/**
 * This class listens for network traffic, filters for ARP packets and generates an ARP table.
 */
public class ArpCapture {

    private static final Logger log = LoggerFactory.getLogger(ArpCapture.class.getName());
    private static final Map<InetAddress, MacAddress> ARP_TABLE = new HashMap<>();
    // Snapshot length, which is the number of bytes captured for each packet.
    private static final int SNAP_LENGTH = 65536;
    private static final int READ_TIMEOUT_MS = 100;
    private static final int PACKET_COUNT = 500;

    public static void main(String[] args) {
        PcapNetworkInterface nif = null;
        try {
            // User selects interface through console
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            log.error(e.getMessage());
        }
        if (nif == null)
            return;

        try (final PcapHandle handle = nif.openLive(SNAP_LENGTH, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS)) {
            // Filter for ARP packets
            handle.setFilter("arp", BpfCompileMode.OPTIMIZE);
            // Listen for ARP packets X amount of times and add the corresponding IP-MAC pairs to the map
            handle.loop(PACKET_COUNT, (PacketListener) packet -> {
                ArpHeader header = (ArpHeader) packet.getPayload().getHeader();
                ARP_TABLE.putIfAbsent(header.getSrcProtocolAddr(), header.getSrcHardwareAddr());
            });
            // Format output table and print
            System.out.println("ARP-Table:\nIP Address\t\tMAC Address\n---------------------------------");
            // Iterate over all IP-MAC pairs and print
            ARP_TABLE.forEach((k, v) -> System.out.println(k.getHostAddress() + "\t\t" + v));
        } catch (NotOpenException | InterruptedException | PcapNativeException e) {
            log.error(e.getMessage());
        }
    }
}
