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

#ifndef __LOW_AND_SLOW_SLOWLORIS_H_
#define __LOW_AND_SLOW_SLOWLORIS_H_

#include <omnetpp.h>

#include "inet/applications/tcpapp/TcpAppBase.h"
#include "inet/common/lifecycle/ILifecycle.h"
#include "inet/common/lifecycle/NodeStatus.h"

using namespace inet;

/**
 * TODO - Generated class
 */
class Slowloris : public TcpAppBase
{
protected:
    cMessage *timeoutMsg = nullptr;
    bool earlySend = false; // if true, don't wait with sendRequest() until established()
    int numRequestsToSend = 0; // requests to send in this session
    simtime_t startTime;
    simtime_t stopTime;

    int req = 0;

    virtual void sendRequest();
    virtual void rescheduleAfterOrDeleteTimer(simtime_t d, short int msgKind);

    virtual std::vector<uint8_t> generateRandomHeader();
    virtual std::vector<uint8_t> randomBytesVector(int amount);

    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleTimer(cMessage *msg) override;

    virtual void socketEstablished(TcpSocket *socket) override;
    virtual void socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent) override;
    virtual void socketClosed(TcpSocket *socket) override;
    virtual void socketFailure(TcpSocket *socket, int code) override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    virtual void close() override;

  public:
    Slowloris() {}
    virtual ~Slowloris();
};

#endif
