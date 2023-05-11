package dns_amplification.simulations;

@license(LGPL);

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.EthernetSwitch;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;

network dns_amplification
{
    parameters:
        double per = default(0);
        int attackersCount = default(1);
    types:
        channel C extends DatarateChannel
        {
            per = parent.per;
        }
    submodules:
        attacker[attackersCount]: StandardHost;
        
        victim: StandardHost;
        
        router: Router;
        
        NIDS: EthernetSwitch;

        configurator: Ipv4NetworkConfigurator;

    connections:
        for i=0..attackersCount-1 {
            attacker[i].ethg++ <--> C <--> router.ethg++;
        }

        router.ethg++ <--> C <--> NIDS.ethg++;

        NIDS.ethg++ <--> C <--> victim.ethg++;
}