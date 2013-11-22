"""Custom topology for DPI

'--topo=dpi'
"""

from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        DPI1 = self.addHost( 'd1' )
        DPI2 = self.addHost( 'd2' )
        Edge4 = self.addSwitch( 's4' )
        Bridge2 = self.addSwitch( 's2' )
        Bridge3 = self.addSwitch( 's3' )
        Edge1 = self.addSwitch( 's1' )
        Web1 = self.addHost( 'w1' )
        Web2 = self.addHost( 'w2' )

        # Add links
        self.addLink( Edge4, DPI1 )
        self.addLink( Edge4, DPI2 )
        self.addLink( Edge4, Bridge2 )
        self.addLink( Edge4, Bridge3 )
        self.addLink( Edge1, Bridge2 )
        self.addLink( Edge1, Bridge3 )
        self.addLink( Edge1, Web1 )
        self.addLink( Edge1, Web2 )


topos = { 'dpi': ( lambda: MyTopo() ) }
