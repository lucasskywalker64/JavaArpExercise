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

    /** Logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger(ArpCapture.class.getName());

    /** Map to store IP addresses and their corresponding MAC addresses */
    private static final Map<InetAddress, MacAddress> ARP_TABLE = new HashMap<>();

    /** Snapshot length, which is the number of bytes captured for each packet */
    private static final int SNAP_LENGTH = 65536;

    /** Timeout in milliseconds for packet capture operations */
    private static final int READ_TIMEOUT_MS = 100;

    /** Number of packets to capture before stopping */
    private static final int PACKET_COUNT = 500;

    /**
     * Main method for capturing ARP packets.
     * 1. Prompts the user to select a network interface for packet capture
     * 2. Opens the selected interface in promiscuous mode
     * 3. Sets a filter to capture only ARP packets
     * 4. Captures a specified number of ARP packets
     * 5. Builds an ARP table mapping IP addresses to MAC addresses
     * 6. Prints the ARP table to the console
     * 
     * @param args command line arguments (not used)
     */
    public static void main(String[] args) {
        PcapNetworkInterface nif = null;
        try {
            // Select a network interface through user interaction
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            LOG.error(e.getMessage());
        }
        if (nif == null)
            return;

        // Open the selected network interface for packet capture
        try (final PcapHandle handle = nif.openLive(SNAP_LENGTH, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS)) {
            // Set a filter to only capture ARP packets
            handle.setFilter("arp", BpfCompileMode.OPTIMIZE);

            // Start capturing packets
            handle.loop(PACKET_COUNT, (PacketListener) packet -> {
                // Extract the ARP header from the captured packet
                ArpHeader header = (ArpHeader) packet.getPayload().getHeader();

                // Add the source IP and MAC address to the ARP table
                ARP_TABLE.putIfAbsent(header.getSrcProtocolAddr(), header.getSrcHardwareAddr());
            });

            // Print the header for the ARP table
            System.out.println("ARP-Table:\nIP Address\t\tMAC Address\n---------------------------------");

            // Iterate over all IP-MAC pairs in the ARP table and print them
            ARP_TABLE.forEach((k, v) -> System.out.println(k.getHostAddress() + "\t\t" + v));
        } catch (NotOpenException | InterruptedException | PcapNativeException e) {
            LOG.error(e.getMessage());
        }
    }
}
