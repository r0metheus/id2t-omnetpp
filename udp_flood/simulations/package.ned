package udp_flood.simulations;

@license(LGPL);

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.EthernetSwitch;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;

network udp_flood
{
    parameters:
        double per = default(0);
        int attackersCount = default(1);
        int victimsCount = default(1);
        @display("bgb=1022.5375,438.72");
    types:
        channel C extends DatarateChannel
        {
            per = parent.per;
        }
    submodules:
        attacker[attackersCount]: StandardHost {
            @display("p=194.94,256.5");
        }
        victim[victimsCount]: StandardHost {
            @display("p=900.315,256.5");
        }
        router: Router {
            @display("p=389.88,256.5");
        }
        NIDS: EthernetSwitch {

            @display("p=655.3575,255.2175");
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

