#!/usr/bin/env php
<?php

/**
  * @desc   Basic stream decoder for Libpcap + IAX2
  *         Usage: tcpdump -U -s0 -w- port 4569 | ./info.php
  *
  * @author Leo Brown <technical@acumensystems.net>
  *
  */

require('../../Classes/udp_decode.class.php');
require('../../Classes/iax_decode.class.php');

$t = new UDP_Decode('php://stdin');
$i = new IAX_Decode();

while( $packet = $t->getPacket() ){

	if(!@$packet['udp']){
		continue;
	}

	$i->load($packet['udp']['packet']);

	if($i->messagetype && $i->messagetype!='voice'){
		print "{$packet['ip']['header']['src']}\t->  {$packet['ip']['header']['dst']}".
		"\t {$i->messagetype}\n";
	}

}

?>
