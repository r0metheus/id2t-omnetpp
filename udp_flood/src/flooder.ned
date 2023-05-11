//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package udp_flood;

import inet.applications.contract.IApp;

simple Flooder like IApp
{
    parameters:
        string interfaceTableModule;   // The path to the InterfaceTable module
        string destAddresses; // space-separated list of destination IP addresses, can be empty;
                              // see module description for possibilities
        bool excludeLocalDestAddresses = default(true);     // excluding local addresses from destAddresses
        bool dnsResponse = default(false);
        string chooseDestAddrMode @enum("once","perBurst","perSend"); // when to change the destination address
        int destAddrRNG = default(0); // random generator ID for selecting a destination address
        int localPort = default(-1);  // local UDP port number (-1: use ephemeral port)
        int destPort; // remote UDP port number
        double startTime @unit(s) = default(1s); // application start time (start of the first burst)
        double stopTime @unit(s) = default(-1s); // application stop time (no packets are sent after this time); a negative or -1 means no limit
        volatile int messageLength @unit(B); // length of messages to generate, in bytes
        volatile double burstDuration @unit(s); // burst duration time (zero not allowed)
        volatile double sleepDuration @unit(s); // time between bursts (zero allowed)
        volatile double sendInterval @unit(s); // time between messages during bursts; usually a random value, e.g. 0.1s+uniform(-0.001s,0.001s); zero not allowed
        double delayLimit @unit(s) = default(0s); // maximum accepted delay for a packet; packets with a bigger delay are discarded (dropped), zero value means no limit
        int timeToLive = default(-1); // if not -1, set the TTL (IPv4) or Hop Limit (IPv6) field of sent packets to this value
        bool dontFragment = default(false); // if true, asks IP to not fragment the message during routing
        int dscp = default(-1); // if not -1, set the DSCP field (on IPv4/IPv6) of sent packets to this value
        int tos = default(-1); // if not -1, set the Type Of Service (IPv4) / Traffic Class (IPv6) field of sent packets to this value
        @display("i=block/app");
        @lifecycleSupport;
        double stopOperationExtraTime @unit(s) = default(-1s);    // extra time after lifecycle stop operation finished
        double stopOperationTimeout @unit(s) = default(2s);    // timeout value for lifecycle stop operation
        @signal[packetSent](type=inet::Packet);
        @signal[packetReceived](type=inet::Packet);
        @signal[packetDropped](type=inet::Packet);
        @signal[outOfOrderPk](type=inet::Packet);
        @statistic[packetSent](title="packets sent"; source=packetSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[packetReceived](title="packets received"; source=packetReceived; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[dropPk](title="packets dropped"; source=packetDropped; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[outOfOrderPk](title="packets received out of order"; source=outOfOrderPk; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[endToEndDelay](title="delay"; source="dataAge(packetReceived)"; unit=s; record=histogram,vector; interpolationmode=none);
    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
}
