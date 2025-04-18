package com.github.lucasskywalker64;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.ArpPacket.ArpHeader;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * This class scans the local network for active devices using ARP requests.
 */
public class ArpScanner {

    /** Logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger(ArpScanner.class);

    /** Network interface used for packet capture and transmission */
    private static final PcapNetworkInterface nif;

    /** MAC address of the local network interface */
    private static final MacAddress SRC_MAC_ADDR;

    /** Map to store IP addresses and their corresponding MAC addresses */
    private static final Map<InetAddress, MacAddress> ARP_TABLE = new HashMap<>();

    /** Maximum number of bytes to capture for each packet */
    private static final int SNAP_LENGTH = 65536;

    /** Timeout in milliseconds for packet capture operation */
    private static final int READ_TIMEOUT_MS = 100;

    /** Network address of the local subnet */
    private static InetAddress netAddr;

    /** Subnet mask of the local network */
    private static byte[] subnetMask;

    static {
        try {
            // Select a network interface through user interaction
            nif = new NifSelector().selectNetworkInterface();
            // Get the MAC address of the selected network interface
            SRC_MAC_ADDR = (MacAddress) nif.getLinkLayerAddresses().getFirst();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Main method that performs the ARP scanning process:
     * 1. Opens packet capture handles for sending and receiving packets
     * 2. Gets all IP addresses in the local subnet
     * 3. Sets up a packet listener to capture ARP responses
     * 4. Creates and sends ARP request packets to all IP addresses
     * 5. Displays the results of the scan
     *
     * @param args command line arguments (not used)
     */
    public static void main(String[] args) {
        try (
                // Open handles for packet capture in promiscuous mode
                PcapHandle receiveHandle = nif.openLive(SNAP_LENGTH, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS);
                PcapHandle sendHandle = nif.openLive(SNAP_LENGTH, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS);
                // Create a thread pool for packet capture
                ExecutorService pool = Executors.newSingleThreadExecutor()) {
            // Get all IP addresses in the local subnet
            List<InetAddress> addresses = getAllAddresses();

            // Set a BPF filter to only capture ARP reply packets (opcode = 2)
            receiveHandle.setFilter("arp[6:2] = 2", BpfCompileMode.OPTIMIZE);

            // Create a packet listener that extracts source IP and MAC addresses from ARP replies
            PacketListener packetListener = packet -> {
                ArpHeader arpHeader = packet.get(ArpPacket.class).getHeader();
                ARP_TABLE.putIfAbsent(arpHeader.getSrcProtocolAddr(), arpHeader.getSrcHardwareAddr());
            };

            // Create and start a task to listen for ARP replies
            Task t = new Task(receiveHandle, packetListener);
            pool.execute(t);

            // Create an ARP packet builder for ARP request packets
            ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
            arpBuilder
                    .hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                    .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                    .operation(ArpOperation.REQUEST).srcHardwareAddr(SRC_MAC_ADDR)
                    .srcProtocolAddr(nif.getAddresses().getFirst().getAddress())
                    .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS);

            // Create an Ethernet packet builder to encapsulate the ARP packet
            EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
            etherBuilder
                    .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                    .srcAddr(SRC_MAC_ADDR)
                    .type(EtherType.ARP)
                    .payloadBuilder(arpBuilder)
                    .paddingAtBuild(true);

            // Send ARP requests to all IP addresses in the subnet
            for (InetAddress addr : addresses) {
                arpBuilder.dstProtocolAddr(addr);
                sendHandle.sendPacket(etherBuilder.build());
                // Wait 1 second between packets to avoid flooding the network
                Thread.sleep(1000);
            }

            // Stop the packet capture
            receiveHandle.breakLoop();

            // Display the scan results
            System.out.printf("Scanning network: %s/%d%n", netAddr.getHostAddress(), convertNetmaskToCIDR(subnetMask));
            System.out.println("-----------------------------");
            System.out.println("Detected devices:");
            System.out.println("IP address\t\tMAC address");
            System.out.println("-----------------------------");
            ARP_TABLE.forEach((k, v) -> System.out.println(k.getHostAddress() + "\t\t" + v));
            System.out.println("-----------------------------");
            System.out.println("Detected active devices: " + ARP_TABLE.size());
        } catch (PcapNativeException | NotOpenException | InterruptedException | UnknownHostException e) {
            LOG.error(e.getMessage());
        }
    }

    /**
     * Calculates all IP addresses in the local subnet based on the network interface's
     * broadcast address and subnet mask.
     *
     * @return A list of all IP addresses in the subnet (excluding network and broadcast addresses)
     * @throws UnknownHostException if there's an error resolving IP addresses
     */
    private static List<InetAddress> getAllAddresses() throws UnknownHostException {
        // Get the broadcast address of the network interface
        byte[] broadcast = nif.getAddresses().getFirst().getBroadcastAddress().getAddress();
        // Get the subnet mask of the network interface
        subnetMask = nif.getAddresses().getFirst().getNetmask().getAddress();
        // Calculate the network address by performing bitwise AND between broadcast and subnet mask
        byte[] network = new byte[4];

        for (int i = 0; i < 4; i++)
            network[i] = (byte) (broadcast[i] & subnetMask[i]);

        // Create an InetAddress object for the network address
        netAddr = InetAddress.getByAddress(network);

        // Convert network and broadcast addresses to integers for easier iteration
        int networkInt = ipToInt(netAddr);
        int broadcastInt = ipToInt(nif.getAddresses().getFirst().getBroadcastAddress());

        // Create a list of all IP addresses in the subnet (excluding network and broadcast addresses)
        List<InetAddress> ipRange = new ArrayList<>();
        for (int i = networkInt + 1; i < broadcastInt; i++) {
            ipRange.add(InetAddress.getByName(intToIp(i)));
        }
        return ipRange;
    }

    /**
     * Converts an IP address from InetAddress format to an integer representation.
     * This makes it easier to perform arithmetic operations on IP addresses.
     *
     * @param ip The IP address to convert
     * @return The integer representation of the IP address
     */
    private static int ipToInt(InetAddress ip) {
        byte[] bytes = ip.getAddress();
        int result = 0;
        // Shift each byte into the result, handling unsigned conversion with & 0xFF
        for (byte b : bytes) {
            result = (result << 8) | (b & 0xFF);
        }
        return result;
    }

    /**
     * Converts an IP address from integer representation to a dotted-decimal string.
     *
     * @param ip The integer representation of the IP address
     * @return The dotted-decimal string representation of the IP address
     */
    private static String intToIp(int ip) {
        // Extract each octet from the integer and format as dotted-decimal
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }

    /**
     * Converts a subnet mask from byte array format to CIDR notation (e.g., /24).
     * This method counts the number of consecutive 1 bits from the most significant bit.
     *
     * @param netmask The subnet mask as a byte array
     * @return The CIDR prefix length
     * @throws IllegalArgumentException if the subnet mask is invalid (contains non-consecutive 1s)
     */
    private static int convertNetmaskToCIDR(byte[] netmask) {
        int cidr = 0;
        boolean zero = false;  // Flag to track if we've seen a 0 bit

        for (byte b : netmask) {
            int mask = 0x80;  // Start with the most significant bit (10000000)

            for (int i = 0; i < 8; i++) {
                int result = b & mask;
                if (result == 0) {
                    // If we encounter a 0 bit, set the flag
                    zero = true;
                } else if (zero) {
                    // If we encounter a 1 bit after seeing a 0 bit, the mask is invalid
                    // (subnet masks must have consecutive 1s followed by consecutive 0s)
                    throw new IllegalArgumentException("Invalid subnet mask.");
                } else {
                    // Count consecutive 1 bits
                    cidr++;
                }
                // Shift the mask right by 1 bit
                mask >>>= 1;
            }
        }
        return cidr;
    }

    /**
     * A record class that implements Runnable to handle packet capture in a separate thread.
     * This class is responsible for starting the packet capture loop and handling any exceptions.
     *
     * @param handle   The packet capture handle to use
     * @param listener The packet listener to process captured packets
     */
    private record Task(PcapHandle handle, PacketListener listener) implements Runnable {
        @Override
        public void run() {
            try {
                // Start the packet capture loop with unlimited count (-1)
                // This will continue until explicitly stopped with breakLoop()
                handle.loop(-1, listener);
            } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                LOG.error(e.getMessage());
            }
        }
    }
}
