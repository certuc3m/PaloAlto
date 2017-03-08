#!/usr/bin/perl

# Documentación utilizada para realizar este script:
# XML API de PaloAlto: https://www.paloaltonetworks.com/documentation/71/pan-os/xml-api
# Módulo LibXML de perl: http://grantm.github.io/perl-libxml-by-example/basics.html
# Extensión del Agente SNMP local para ejecutar código perl: https://vincent.bernat.im/en/blog/2012-extending-netsnmp
# MIB de Cisco para la tabla ARP: http://networkengineering.stackexchange.com/questions/2900/using-snmp-to-retrieve-the-arp-and-mac-address-tables-from-a-switch

# La respuesta es similar a:
#<response status="success"><result>
#  <max>32000</max>
#  <total>540</total>
#  <timeout>1800</timeout>
#  <dp>dp1</dp>
#  <entries>
#    <entry>
#      <status>  c  </status>
#      <ip>163.117.163.3</ip>
#      <mac>00:13:21:0b:8b:de</mac>
#      <ttl>1646</ttl>
#      <interface>vlan</interface>
#      <port>ethernet1/9</port>
#    </entry>
#    <entry>
#      <status>  c  </status>
#      <ip>163.117.49.4</ip>
#      <mac>00:19:a9:2f:ec:00</mac>
#      <ttl>542</ttl>
#      <interface>ethernet1/12.49</interface>
#      <port>ethernet1/12</port>
#    </entry>
#    <entry>
#      <status>  c  </status>
#      <ip>163.117.49.15</ip>
#      <mac>40:f4:ec:c9:e3:c1</mac>
#      <ttl>687</ttl>
#      <interface>ethernet1/12.49</interface>
#      <port>ethernet1/12</port>
#    </entry>
#    ....

use XML::LibXML;
use SNMP::Extension::PassPersist;

# MIB Base para la tabla ARP.
$base = ".1.3.6.1.2.1.3.1.1.2";

# Datos del FW de donde se coge la tabla ARP
# DNS or IP address of your firewall
$fw="";

# Key to access to API, check PA documentation to generate one on your FW
$key="";
$url_arp="/api/?type=op&cmd=<show><arp><entry name = 'all'/></arp></show>&key=$key";


my $extsnmp = SNMP::Extension::PassPersist->new(
    backend_collect => \&update_tree,
    refresh	    => 900
    );
$extsnmp->run;


sub update_tree {
	my ($self) = @_;

	$wget='/usr/bin/wget --no-check-certificate --quiet -O - "https://' . $fw . $url_arp . '"';

	open (ARP, $wget . '|');

	@ARP = <ARP>;

	$resp=join('', @ARP);
	#print $resp;


	$dom = XML::LibXML->load_xml(string => $resp);

	# Para cada entrada en la tabla ARP del FW
	foreach my $title ($dom->findnodes('/response/result/entries/entry')) {
                #print "IP: " . $title->findvalue('ip') ." -> MAC: ". $title->findvalue('mac') .
                #       " Interface: " . $title->findvalue('interface') ." -> Port: ". $title->findvalue('port') . "\n";

                ($interfaz,$vlan)=split(/\./,$title->findvalue('interface'));
                $oid = $base . '.' . $vlan . '.' . $title->findvalue('ip');
                $ip = $title->findvalue('ip');
                $mac=$title->findvalue('mac');

                $mac =~ s/:/ /g;
if ($mac =~ m/^([0-9A-Fa-f]{2}[ ]){5}([0-9A-Fa-f]{2})/) {
                        $extsnmp->add_oid_entry($oid,"octetstr",$mac);
                } else {
                        #print "No es una MAC: $vlan $ip $mac\n";
                }
	}
}
