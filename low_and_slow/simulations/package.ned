package low_and_slow.simulations;

@license(LGPL);

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.EthernetSwitch;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;

network LowAndSlow
{
    parameters:
        double per = default(0);
        int attackersCount = default(1);
        int victimsCount = default(1);
        @display("bgb=1022.5375,438.72");
    types:
        channel C extends DatarateChannel
        {
            datarate = 1Gbps;
            delay = 0.1us;
            per = parent.per;
        }
    submodules:
        attacker[attackersCount]: StandardHost {
            @display("p=107.729996,352.6875");
        }
        victim[victimsCount]: StandardHost {
            @display("p=775.9125,124.4025");
        }
        router: Router {
            @display("p=406.5525,124.4025");
        }
        NIDS: EthernetSwitch {

            @display("p=614.3175,123.12");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=117.6775,43.415");
        }

    connections:
        for i=0..attackersCount-1 {
            attacker[i].ethg++ <--> C <--> router.ethg++;
        }

        router.ethg++ <--> C <--> NIDS.ethg++;

        for i=0..victimsCount-1 {
            NIDS.ethg++ <--> C <--> victim[i].ethg++;
        }
}

