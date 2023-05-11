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

#include "flooder.h"
#include <omnetpp.h>

#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/FragmentationTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"
#include "inet/common/Compat.h"

#include <map>

#include <vector>

#include <inet/applications/base/ApplicationBase.h>
#include <inet/transportlayer/contract/udp/UdpSocket.h>
#include <inet/common/Compat.h>

using namespace inet;

Define_Module(Flooder);

Register_Enum2(destAddrMode, "inet::ChooseDestAddrMode", (
        "once", Flooder::ONCE,
        "perBurst", Flooder::PER_BURST,
        "perSend", Flooder::PER_SEND,
        nullptr
        ));

simsignal_t Flooder::outOfOrderPkSignal = registerSignal("outOfOrderPk");

uint16_t transaction_c;

std::vector<uint8_t> static_dns_response = {
  0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03,
  0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
  0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
  0x00, 0x00, 0xff, 0x00, 0x01, 0xc0, 0x0c, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x9c, 0xd8, 0x00,
  0x04, 0x5d, 0xb8, 0xd8, 0x22, 0xc0, 0x0c, 0x00,
  0x2e, 0x00, 0x01, 0x00, 0x00, 0x9c, 0xd8, 0x00,
  0x9f, 0x00, 0x01, 0x08, 0x02, 0x00, 0x01, 0x51,
  0x80, 0x64, 0x5d, 0xa6, 0x51, 0x64, 0x42, 0x32,
  0xaf, 0x1f, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6d,
  0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
  0x2b, 0xfd, 0xae, 0x4b, 0x71, 0xec, 0x57, 0xd6,
  0x5b, 0xaf, 0xd3, 0xc6, 0xd1, 0x55, 0x84, 0x81,
  0xe2, 0x73, 0x39, 0x41, 0x51, 0xb7, 0x48, 0x22,
  0x5d, 0xeb, 0x9b, 0x45, 0x70, 0x1d, 0x52, 0xdb,
  0x40, 0xef, 0x5c, 0x60, 0xa8, 0xb9, 0x64, 0x5f,
  0x1f, 0x44, 0x91, 0xc7, 0x4a, 0x6b, 0x31, 0x36,
  0xa0, 0x88, 0x0c, 0x7c, 0x62, 0x0b, 0x25, 0x2e,
  0x80, 0x61, 0x22, 0xae, 0x37, 0x0e, 0x01, 0x20,
  0xd0, 0x6c, 0xaa, 0x4e, 0x62, 0xd9, 0xc7, 0x4f,
  0x89, 0xad, 0xb4, 0x70, 0xd4, 0x59, 0x74, 0x5a,
  0x3f, 0x54, 0xe3, 0x28, 0x82, 0x1f, 0x99, 0x5c,
  0xd5, 0x68, 0xab, 0xc8, 0xbb, 0x5d, 0xf5, 0xe3,
  0x1f, 0x66, 0xe2, 0x9e, 0xe4, 0xf5, 0x2d, 0xdb,
  0x1a, 0x34, 0x2f, 0x2d, 0xf4, 0xc0, 0xd6, 0xcf,
  0x67, 0x91, 0x57, 0x35, 0x72, 0x8d, 0x48, 0xa7,
  0xfb, 0xae, 0xef, 0x8c, 0xd8, 0x32, 0x1b, 0x07,
  0xc0, 0x0c, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00,
  0x9c, 0xd8, 0x00, 0x5f, 0x00, 0x01, 0x0d, 0x02,
  0x00, 0x01, 0x51, 0x80, 0x64, 0x5d, 0xa6, 0x51,
  0x64, 0x42, 0x32, 0xaf, 0x21, 0xfd, 0x07, 0x65,
  0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
  0x6f, 0x6d, 0x00, 0x58, 0x97, 0xf7, 0x53, 0x5e,
  0x69, 0x46, 0xcf, 0x3b, 0x03, 0x3f, 0x42, 0x58,
  0x35, 0x12, 0xd8, 0x21, 0xea, 0x7e, 0x10, 0x1a,
  0xb1, 0xbf, 0xac, 0x67, 0x33, 0xc5, 0x2b, 0x59,
  0x81, 0xd0, 0x46, 0x5b, 0xea, 0x4c, 0x1e, 0x87,
  0x72, 0x3b, 0x22, 0x46, 0x5d, 0xd4, 0x1b, 0xc6,
  0x49, 0xac, 0x19, 0xf8, 0x2f, 0xe6, 0xe6, 0x18,
  0x02, 0xc2, 0x05, 0x6f, 0xc1, 0x62, 0x17, 0x7c,
  0x23, 0x2f, 0x7b
};

std::vector<uint8_t> transaction_id = {0x00, 0x00};

std::vector<uint8_t> dns_query = {0x81, 0x80, 0x00, 0x01, 0x00,
                                0x03, 0x00, 0x00, 0x00, 0x00,
                                0x07, 0x65, 0x78, 0x61, 0x6d,
                                0x70, 0x6c, 0x65, 0x03, 0x63,
                                0x6f, 0x6d, 0x00, 0x00, 0xff,
                                0x00, 0x01};

std::vector<uint8_t> dns_answers = {0xc0, 0x0c, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x9c, 0xd8, 0x00,
  0x04, 0x5d, 0xb8, 0xd8, 0x22, 0xc0, 0x0c, 0x00,
  0x2e, 0x00, 0x01, 0x00, 0x00, 0x9c, 0xd8, 0x00,
  0x9f, 0x00, 0x01, 0x08, 0x02, 0x00, 0x01, 0x51,
  0x80, 0x64, 0x5d, 0xa6, 0x51, 0x64, 0x42, 0x32,
  0xaf, 0x1f, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6d,
  0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
  0x2b, 0xfd, 0xae, 0x4b, 0x71, 0xec, 0x57, 0xd6,
  0x5b, 0xaf, 0xd3, 0xc6, 0xd1, 0x55, 0x84, 0x81,
  0xe2, 0x73, 0x39, 0x41, 0x51, 0xb7, 0x48, 0x22,
  0x5d, 0xeb, 0x9b, 0x45, 0x70, 0x1d, 0x52, 0xdb,
  0x40, 0xef, 0x5c, 0x60, 0xa8, 0xb9, 0x64, 0x5f,
  0x1f, 0x44, 0x91, 0xc7, 0x4a, 0x6b, 0x31, 0x36,
  0xa0, 0x88, 0x0c, 0x7c, 0x62, 0x0b, 0x25, 0x2e,
  0x80, 0x61, 0x22, 0xae, 0x37, 0x0e, 0x01, 0x20,
  0xd0, 0x6c, 0xaa, 0x4e, 0x62, 0xd9, 0xc7, 0x4f,
  0x89, 0xad, 0xb4, 0x70, 0xd4, 0x59, 0x74, 0x5a,
  0x3f, 0x54, 0xe3, 0x28, 0x82, 0x1f, 0x99, 0x5c,
  0xd5, 0x68, 0xab, 0xc8, 0xbb, 0x5d, 0xf5, 0xe3,
  0x1f, 0x66, 0xe2, 0x9e, 0xe4, 0xf5, 0x2d, 0xdb,
  0x1a, 0x34, 0x2f, 0x2d, 0xf4, 0xc0, 0xd6, 0xcf,
  0x67, 0x91, 0x57, 0x35, 0x72, 0x8d, 0x48, 0xa7,
  0xfb, 0xae, 0xef, 0x8c, 0xd8, 0x32, 0x1b, 0x07,
  0xc0, 0x0c, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00,
  0x9c, 0xd8, 0x00, 0x5f, 0x00, 0x01, 0x0d, 0x02,
  0x00, 0x01, 0x51, 0x80, 0x64, 0x5d, 0xa6, 0x51,
  0x64, 0x42, 0x32, 0xaf, 0x21, 0xfd, 0x07, 0x65,
  0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
  0x6f, 0x6d, 0x00, 0x58, 0x97, 0xf7, 0x53, 0x5e,
  0x69, 0x46, 0xcf, 0x3b, 0x03, 0x3f, 0x42, 0x58,
  0x35, 0x12, 0xd8, 0x21, 0xea, 0x7e, 0x10, 0x1a,
  0xb1, 0xbf, 0xac, 0x67, 0x33, 0xc5, 0x2b, 0x59,
  0x81, 0xd0, 0x46, 0x5b, 0xea, 0x4c, 0x1e, 0x87,
  0x72, 0x3b, 0x22, 0x46, 0x5d, 0xd4, 0x1b, 0xc6,
  0x49, 0xac, 0x19, 0xf8, 0x2f, 0xe6, 0xe6, 0x18,
  0x02, 0xc2, 0x05, 0x6f, 0xc1, 0x62, 0x17, 0x7c,
  0x23, 0x2f, 0x7b};

Flooder::~Flooder()
{
    cancelAndDelete(timerNext);
}

void Flooder::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        counter = 0;
        numSent = 0;
        numReceived = 0;
        numDeleted = 0;
        numDuplicated = 0;
        transaction_c = 0;

        delayLimit = par("delayLimit");
        startTime = par("startTime");
        stopTime = par("stopTime");
        if (stopTime >= SIMTIME_ZERO && stopTime <= startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");

        messageLengthPar = &par("messageLength");
        burstDurationPar = &par("burstDuration");
        sleepDurationPar = &par("sleepDuration");
        sendIntervalPar = &par("sendInterval");
        dnsResponse = par("dnsResponse");

        nextSleep = startTime;
        nextBurst = startTime;
        nextPkt = startTime;
        dontFragment = par("dontFragment");

        destAddrRNG = par("destAddrRNG");
        const char *addrModeStr = par("chooseDestAddrMode");
        int addrMode = cEnum::get("inet::ChooseDestAddrMode")->lookup(addrModeStr);
        if (addrMode == -1)
            throw cRuntimeError("Invalid chooseDestAddrMode: '%s'", addrModeStr);
        chooseDestAddrMode = static_cast<ChooseDestAddrMode>(addrMode);

        WATCH(numSent);
        WATCH(numReceived);
        WATCH(numDeleted);
        WATCH(numDuplicated);

        localPort = par("localPort");
        destPort = par("destPort");

        timerNext = new cMessage("UDPFlooderTimer");
    }
}

L3Address Flooder::chooseDestAddr()
{
    if (destAddresses.size() == 1)
        return destAddresses[0];

    int k = getRNG(destAddrRNG)->intRand(destAddresses.size());
    return destAddresses[k];
}

Packet *Flooder::createPacket()
{
    char msgName[32];
    sprintf(msgName, "FlooderData-%lu", (unsigned long)counter++);
    long msgByteLength = *messageLengthPar;

    Packet *pk = nullptr;

    if (dnsResponse){
        std::vector<uint8_t> dns_response = {static_cast<uint8_t>((transaction_c >> 8) & 0xff), static_cast<uint8_t>((transaction_c) & 0xff)};
        transaction_c++;

        dns_response.insert(dns_response.end(), dns_query.begin(), dns_query.end());

        dns_response.insert(dns_response.end(), dns_answers.begin(), dns_answers.end());

        auto rawBytesData = makeShared<BytesChunk>();
        rawBytesData->setBytes(dns_response);

        pk = new Packet(msgName, rawBytesData);

    }

    else {
        pk = new Packet(msgName);

        const auto& payload = makeShared<ApplicationPacket>();
        payload->setChunkLength(B(msgByteLength));
        payload->setSequenceNumber(numSent);
        payload->addTag<CreationTimeTag>()->setCreationTime(simTime());
        pk->insertAtBack(payload);
        pk->addPar("sourceId") = getId();
        pk->addPar("msgId") = numSent;

    }

    return pk;
}

void Flooder::processStart()
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(localPort);

    int timeToLive = par("timeToLive");
    if (timeToLive != -1)
        socket.setTimeToLive(timeToLive);

    int dscp = par("dscp");
    if (dscp != -1)
        socket.setDscp(dscp);

    int tos = par("tos");
    if (tos != -1)
        socket.setTos(tos);

    const char *destAddrs = par("destAddresses");
    cStringTokenizer tokenizer(destAddrs);
    const char *token;
    bool excludeLocalDestAddresses = par("excludeLocalDestAddresses");

    IInterfaceTable *ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);

    while ((token = tokenizer.nextToken()) != nullptr) {
        if (strstr(token, "Broadcast") != nullptr)
            destAddresses.push_back(Ipv4Address::ALLONES_ADDRESS);
        else {
            L3Address addr = L3AddressResolver().resolve(token);
            if (excludeLocalDestAddresses && ift && ift->isLocalAddress(addr))
                continue;
            destAddresses.push_back(addr);
        }
    }

    nextSleep = simTime();
    nextBurst = simTime();
    nextPkt = simTime();
    activeBurst = false;

    isSource = !destAddresses.empty();

    if (isSource) {
        if (chooseDestAddrMode == ONCE)
            destAddr = chooseDestAddr();

        activeBurst = true;
    }
    timerNext->setKind(SEND);
    processSend();
}

void Flooder::processSend()
{
    if (stopTime < SIMTIME_ZERO || simTime() < stopTime) {
        // send and reschedule next sending
        if (isSource) // if the node is a sink, don't generate messages
            generateBurst();
    }
}

void Flooder::processStop()
{
    socket.close();
    socket.setCallback(nullptr);
}

void Flooder::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        switch (msg->getKind()) {
            case START:
                processStart();
                break;

            case SEND:
                processSend();
                break;

            case STOP:
                processStop();
                break;

            default:
                throw cRuntimeError("Invalid kind %d in self message", (int)msg->getKind());
        }
    }
    else
        socket.processMessage(msg);
}

void Flooder::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    // process incoming packet
    processPacket(packet);
}

void Flooder::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void Flooder::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

void Flooder::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

void Flooder::processPacket(Packet *pk)
{
    if (pk->getKind() == UDP_I_ERROR) {
        EV_WARN << "UDP error received\n";
        delete pk;
        return;
    }

    if (pk->hasPar("sourceId") && pk->hasPar("msgId")) {
        // duplicate control
        int moduleId = pk->par("sourceId");
        int msgId = pk->par("msgId");
        auto it = sourceSequence.find(moduleId);
        if (it != sourceSequence.end()) {
            if (it->second >= msgId) {
                EV_DEBUG << "Out of order packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
                emit(outOfOrderPkSignal, pk);
                delete pk;
                numDuplicated++;
                return;
            }
            else
                it->second = msgId;
        }
        else
            sourceSequence[moduleId] = msgId;
    }

    if (delayLimit > 0) {
        if (simTime() - pk->getTimestamp() > delayLimit) {
            EV_DEBUG << "Old packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
            PacketDropDetails details;
            details.setReason(CONGESTION);
            emit(packetDroppedSignal, pk, &details);
            delete pk;
            numDeleted++;
            return;
        }
    }

    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk) << endl;
    emit(packetReceivedSignal, pk);
    numReceived++;
    delete pk;
}

void Flooder::generateBurst()
{
    simtime_t now = simTime();

    if (nextPkt < now)
        nextPkt = now;

    double sendInterval = *sendIntervalPar;
    if (sendInterval <= 0.0)
        throw cRuntimeError("The sendInterval parameter must be bigger than 0");
    nextPkt += sendInterval;

    if (activeBurst && nextBurst <= now) { // new burst
        double burstDuration = *burstDurationPar;
        if (burstDuration < 0.0)
            throw cRuntimeError("The burstDuration parameter mustn't be smaller than 0");
        double sleepDuration = *sleepDurationPar;

        if (burstDuration == 0.0)
            activeBurst = false;
        else {
            if (sleepDuration < 0.0)
                throw cRuntimeError("The sleepDuration parameter mustn't be smaller than 0");
            nextSleep = now + burstDuration;
            nextBurst = nextSleep + sleepDuration;
        }

        if (chooseDestAddrMode == PER_BURST)
            destAddr = chooseDestAddr();
    }

    if (chooseDestAddrMode == PER_SEND)
        destAddr = chooseDestAddr();

    Packet *payload = createPacket();
    if (dontFragment)
        payload->addTag<FragmentationReq>()->setDontFragment(true);
    payload->setTimestamp();
    emit(packetSentSignal, payload);
    socket.sendTo(payload, destAddr, destPort);
    numSent++;

    // Next timer
    if (activeBurst && nextPkt >= nextSleep)
        nextPkt = nextBurst;

    if (stopTime >= SIMTIME_ZERO && nextPkt >= stopTime) {
        timerNext->setKind(STOP);
        nextPkt = stopTime;
    }
    scheduleAt(nextPkt, timerNext);
}

void Flooder::finish()
{
    recordScalar("Total sent", numSent);
    recordScalar("Total received", numReceived);
    recordScalar("Total deleted", numDeleted);
    ApplicationBase::finish();
}

void Flooder::handleStartOperation(LifecycleOperation *operation)
{
    simtime_t start = std::max(startTime, simTime());

    if ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        timerNext->setKind(START);
        scheduleAt(start, timerNext);
    }
}

void Flooder::handleStopOperation(LifecycleOperation *operation)
{
    if (timerNext)
        cancelEvent(timerNext);
    activeBurst = false;
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void Flooder::handleCrashOperation(LifecycleOperation *operation)
{
    if (timerNext)
        cancelEvent(timerNext);
    activeBurst = false;
    if (operation->getRootModule() != getContainingNode(this)) // closes socket when the application crashed only
        socket.destroy(); // TODO  in real operating systems, program crash detected by OS and OS closes sockets of crashed programs.
}

