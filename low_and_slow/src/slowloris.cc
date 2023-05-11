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

#include "slowloris.h"

#include "inet/applications/tcpapp/GenericAppMsg_m.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/packet/Packet.h"

#include <random>

using namespace inet;

Define_Module(Slowloris);

#define MSGKIND_CONNECT    0
#define MSGKIND_SEND       1

std::vector<uint8_t> init_chunk_first = {0x47, 0x45, 0x54, 0x20, 0x2f, 0x3f};

std::vector<uint8_t> init_chunk_second = {0x20, 0x48, 0x54, 0x54, 0x50,
                                          0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a};

std::vector<uint8_t> user_agent = {0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65,
                                    0x6e, 0x74, 0x3a, 0x20, 0x4d, 0x6f, 0x7a, 0x69,
                                    0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20,
                                    0x28, 0x4d, 0x61, 0x63, 0x69, 0x6e, 0x74, 0x6f,
                                    0x73, 0x68, 0x3b, 0x20, 0x49, 0x6e, 0x74, 0x65,
                                    0x6c, 0x20, 0x4d, 0x61, 0x63, 0x20, 0x4f, 0x53,
                                    0x20, 0x58, 0x20, 0x31, 0x30, 0x5f, 0x31, 0x31,
                                    0x5f, 0x36, 0x29, 0x20, 0x41, 0x70, 0x70, 0x6c,
                                    0x65, 0x57, 0x65, 0x62, 0x4b, 0x69, 0x74, 0x2f,
                                    0x35, 0x33, 0x37, 0x2e, 0x33, 0x36, 0x20, 0x28,
                                    0x4b, 0x48, 0x54, 0x4d, 0x4c, 0x2c, 0x20, 0x6c,
                                    0x69, 0x6b, 0x65, 0x20, 0x47, 0x65, 0x63, 0x6b,
                                    0x6f, 0x29, 0x20, 0x43, 0x68, 0x72, 0x6f, 0x6d,
                                    0x65, 0x2f, 0x35, 0x33, 0x2e, 0x30, 0x2e, 0x32,
                                    0x37, 0x38, 0x35, 0x2e, 0x31, 0x34, 0x33, 0x20,
                                    0x53, 0x61, 0x66, 0x61, 0x72, 0x69, 0x2f, 0x35,
                                    0x33, 0x37, 0x2e, 0x33, 0x36, 0x0d, 0x0a, 0x41,
                                    0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c, 0x61,
                                    0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 0x20,
                                    0x65, 0x6e, 0x2d, 0x55, 0x53, 0x2c, 0x65, 0x6e,
                                    0x2c, 0x71, 0x3d, 0x30, 0x2e, 0x35, 0x0d, 0x0a,
                                    0x58, 0x2d, 0x61, 0x3a, 0x20, 0x33, 0x39, 0x32,
                                    0x32, 0x0d, 0x0a};

Slowloris::~Slowloris()
{
    cancelAndDelete(timeoutMsg);
}

std::vector<uint8_t> Slowloris::randomBytesVector(int amount) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(48, 57);
    std::vector<uint8_t> ret(amount);

    for (int i = 0; i < amount; i++) {
        ret[i] = dis(gen);
    }

    return ret;
}

std::vector<uint8_t> Slowloris::generateRandomHeader() {

    std::vector<uint8_t> header = {0x58, 0x2d, 0x61, 0x3a, 0x20};
    std::vector<uint8_t> ret = {0x0d, 0x0a};

    std::vector<uint8_t> header_val = randomBytesVector(4);

    header.insert(header.end(), header_val.begin(), header_val.end());
    header.insert(header.end(), ret.begin(), ret.end());

    return header;
}

void Slowloris::initialize(int stage)
{
    TcpAppBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        numRequestsToSend = 0;
        earlySend = false; // TODO make it parameter
        WATCH(numRequestsToSend);
        WATCH(earlySend);

        startTime = par("startTime");
        stopTime = par("stopTime");
        if (stopTime >= SIMTIME_ZERO && stopTime < startTime)
            throw cRuntimeError("Invalid startTime/stopTime parameters");
        timeoutMsg = new cMessage("timer");
    }
}

void Slowloris::handleStartOperation(LifecycleOperation *operation)
{
    simtime_t now = simTime();
    simtime_t start = std::max(startTime, now);
    if (timeoutMsg && ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime))) {
        timeoutMsg->setKind(MSGKIND_CONNECT);
        scheduleAt(start, timeoutMsg);
    }
}

void Slowloris::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(timeoutMsg);
    if (socket.getState() == TcpSocket::CONNECTED || socket.getState() == TcpSocket::CONNECTING || socket.getState() == TcpSocket::PEER_CLOSED)
        close();
}

void Slowloris::handleCrashOperation(LifecycleOperation *operation)
{
    cancelEvent(timeoutMsg);
    if (operation->getRootModule() != getContainingNode(this))
        socket.destroy();
}

void Slowloris::sendRequest()
{
    auto rawBytesData = makeShared<BytesChunk>();

   if (0 == req) {
       std::vector<uint8_t> init_chunk = init_chunk_first;
       std::vector<uint8_t> randomReq = randomBytesVector(4);
       init_chunk.insert(init_chunk.end(), randomReq.begin(), randomReq.end());
       init_chunk.insert(init_chunk.end(), init_chunk_second.begin(), init_chunk_second.end());

       rawBytesData->setBytes(init_chunk);
    }

    else if (1 == req) {
        rawBytesData->setBytes(user_agent);
    }

    else if (req > 1){
        rawBytesData->setBytes(generateRandomHeader());
    }

    Packet *packet = new Packet("data", rawBytesData);

    EV_INFO << "remaining " << numRequestsToSend - 1 << " request\n";

    sendPacket(packet);

    req++;
}

void Slowloris::handleTimer(cMessage *msg)
{
    switch (msg->getKind()) {
        case MSGKIND_CONNECT:
            connect(); // active OPEN

            // significance of earlySend: if true, data will be sent already
            // in the ACK of SYN, otherwise only in a separate packet (but still
            // immediately)
            if (earlySend)
                sendRequest();
            break;

        case MSGKIND_SEND: {
            sendRequest();
            numRequestsToSend--;

            if (numRequestsToSend > 0){
                simtime_t d = par("thinkTime");
                rescheduleAfterOrDeleteTimer(d, MSGKIND_SEND);
            }

            break;
        }

        default:
            throw cRuntimeError("Invalid timer msg: kind=%d", msg->getKind());
    }
}

void Slowloris::socketEstablished(TcpSocket *socket)
{
    TcpAppBase::socketEstablished(socket);

    // determine number of requests in this session
    numRequestsToSend = par("numRequestsPerSession");
    if (numRequestsToSend < 1)
        numRequestsToSend = 1;

    // perform first request if not already done (next one will be sent when reply arrives)
    if (!earlySend)
        sendRequest();

    numRequestsToSend--;

    simtime_t d = par("thinkTime");
    rescheduleAfterOrDeleteTimer(d, MSGKIND_SEND);

}

void Slowloris::rescheduleAfterOrDeleteTimer(simtime_t d, short int msgKind)
{
    if (stopTime < SIMTIME_ZERO || simTime() + d < stopTime) {
        timeoutMsg->setKind(msgKind);
        rescheduleAfter(d, timeoutMsg);
    }
    else {
        cancelAndDelete(timeoutMsg);
        timeoutMsg = nullptr;
    }
}

void Slowloris::socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent)
{
    TcpAppBase::socketDataArrived(socket, msg, urgent);

    if (numRequestsToSend > 0) {
        EV_INFO << "reply arrived\n";

        if (timeoutMsg) {
            simtime_t d = par("thinkTime");
            rescheduleAfterOrDeleteTimer(d, MSGKIND_SEND);
        }
    }
    else if (socket->getState() != TcpSocket::LOCALLY_CLOSED) {
        EV_INFO << "reply to last request arrived, closing session\n";
        close();
    }
}

void Slowloris::close()
{
    TcpAppBase::close();
    cancelEvent(timeoutMsg);
}

void Slowloris::socketClosed(TcpSocket *socket)
{
    TcpAppBase::socketClosed(socket);

    // start another session after a delay
    if (timeoutMsg) {
        simtime_t d = par("idleInterval");
        rescheduleAfterOrDeleteTimer(d, MSGKIND_CONNECT);
    }
}

void Slowloris::socketFailure(TcpSocket *socket, int code)
{
    TcpAppBase::socketFailure(socket, code);

    // reconnect after a delay
    if (timeoutMsg) {
        simtime_t d = par("reconnectInterval");
        rescheduleAfterOrDeleteTimer(d, MSGKIND_CONNECT);
    }
}
