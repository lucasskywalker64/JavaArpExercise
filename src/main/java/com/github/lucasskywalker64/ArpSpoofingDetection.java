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

    private static final Logger LOG = LoggerFactory.getLogger(ArpSpoofingDetection.class);
    private static final Map<InetAddress, List<MacAddress>> ARP_TABLE = new HashMap<>();

    /**
     * Main method to detect ARP spoofing in a PCAP file.
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
            handle.setFilter("arp", BpfCompileMode.OPTIMIZE);

            // Process each packet in the PCAP file
            handle.loop(-1, (PacketListener) packet -> {
                ArpHeader header = (ArpHeader) packet.getPayload().getHeader();

                // Add the source IP and MAC address to the ARP table
                ARP_TABLE.compute(header.getSrcProtocolAddr(), (_, v) -> {
                    arpPackets.getAndIncrement();
                    if (v == null) {
                        v = new ArrayList<>();
                    }
                    if (!v.contains(header.getSrcHardwareAddr()))
                        v.add(header.getSrcHardwareAddr());
                    return v;
                });
            });

            // Print the results
            System.out.printf("ARP packet filtering finished: %d ARP packets found.%n", arpPackets.get());
            System.out.println("-------------------------------------");
            System.out.println("Suspicious IP addresses found:");

            // Counter for suspicious IP addresses
            AtomicInteger suspiciousCount = new AtomicInteger(0);
            AtomicInteger i = new AtomicInteger(1);

            // Iterate through the ARP table and print suspicious entries
            ARP_TABLE.forEach((k, v) -> {
                if (v.size() > 1) {
                    suspiciousCount.incrementAndGet();
                    System.out.printf("%d. IP address: %s%n", i.getAndIncrement(), k.getHostAddress());
                    System.out.println("    Registered MAC addresses:");
                    v.forEach(macAddress -> System.out.println("    - " + macAddress.toString()));
                }
            });

            // Print summary
            System.out.println("-------------------------------------");
            System.out.println("Summary:");
            System.out.println("Checked IP addresses: " + ARP_TABLE.size());
            System.out.println("Suspicious IP addresses: " + suspiciousCount.get());

        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            LOG.error(e.getMessage(), e);
        }
    }
}
