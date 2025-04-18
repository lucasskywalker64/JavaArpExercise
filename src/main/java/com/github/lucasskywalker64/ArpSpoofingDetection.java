package com.github.lucasskywalker64;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.ArpPacket.ArpHeader;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class reads pcap files, filters for ARP packages and checks for ARP spoofing.
 */
public class ArpSpoofingDetection {

    /** Logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger(ArpSpoofingDetection.class);

    /** ARP table that maps IP addresses to a list of MAC addresses */
    private static final Map<InetAddress, List<MacAddress>> ARP_TABLE = new HashMap<>();

    /**
     * Main method to detect ARP spoofing in a PCAP file.
     * 1. Opens a PCAP file specified in the command line arguments
     * 2. Filters for ARP packets only
     * 3. Processes each ARP packet to build an ARP table mapping IP addresses to MAC addresses
     * 4. Identifies suspicious IP addresses (those with multiple MAC addresses)
     * 5. Prints a summary of the findings
     * 
     * @param args Command line arguments. Expects a single argument: the path to the PCAP file.
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java ArpSpoofingDetection <Pcap file>");
            return;
        }

        // Counter for the number of ARP packets processed
        AtomicInteger arpPackets = new AtomicInteger();
        try (PcapHandle handle = Pcaps.openOffline(args[0])) {
            // Set a filter to only process ARP packets from the PCAP file
            handle.setFilter("arp", BpfCompileMode.OPTIMIZE);

            // Process each packet in the PCAP file
            handle.loop(-1, (PacketListener) packet -> {
                // Extract the ARP header from the packet
                ArpHeader header = (ArpHeader) packet.getPayload().getHeader();

                // Add the source IP and MAC address to the ARP table
                ARP_TABLE.compute(header.getSrcProtocolAddr(), (_, v) -> {
                    // Increment the counter for each ARP packet processed
                    arpPackets.getAndIncrement();

                    // If this is the first time seeing this IP, create a new list for its MAC addresses
                    if (v == null) {
                        v = new ArrayList<>();
                    }

                    // Add the MAC address to the list if it's not already there
                    if (!v.contains(header.getSrcHardwareAddr()))
                        v.add(header.getSrcHardwareAddr());
                    return v;
                });
            });

            // Print the results of the ARP packet analysis
            System.out.printf("ARP packet filtering finished: %d ARP packets found.%n", arpPackets.get());
            System.out.println("-------------------------------------");
            System.out.println("Suspicious IP addresses found:");

            // Counter for suspicious IP addresses (those with multiple MAC addresses)
            AtomicInteger suspiciousCount = new AtomicInteger(0);
            // Counter for numbering the suspicious IP addresses in the output
            AtomicInteger i = new AtomicInteger(1);

            // Iterate through the ARP table and identify suspicious entries
            // An entry is suspicious if an IP address has more than one MAC address
            ARP_TABLE.forEach((k, v) -> {
                // Check if this IP has multiple MAC addresses
                if (v.size() > 1) {
                    // Increment the counter of suspicious IP addresses
                    suspiciousCount.incrementAndGet();
                    // Print the suspicious IP address
                    System.out.printf("%d. IP address: %s%n", i.getAndIncrement(), k.getHostAddress());
                    System.out.println("    Registered MAC addresses:");
                    // Print all MAC addresses associated with this IP
                    v.forEach(macAddress -> System.out.println("    - " + macAddress.toString()));
                }
            });

            // Print summary of the analysis
            System.out.println("-------------------------------------");
            System.out.println("Summary:");
            // Total number of unique IP addresses found in the ARP packets
            System.out.println("Checked IP addresses: " + ARP_TABLE.size());
            // Number of IP addresses with multiple MAC addresses (suspicious)
            System.out.println("Suspicious IP addresses: " + suspiciousCount.get());

        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            LOG.error(e.getMessage(), e);
        }
    }
}
