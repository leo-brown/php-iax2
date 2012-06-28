<?php

require('Classes/udp_decode.class.php');
require('Classes/iax_decode.class.php');
require('Classes/call_register.class.php');

$t = new UDP_Decode('php://stdin');
$i = new IAX_Decode();

CallRegister::$servers=array(
        '/127.0.0.1/',
);

$captureTypes = array(
	'accept',
	'new',
	'auth_challenge',
	'auth_response',
	'hangup'
);

while($packets = $t->getPackets(1)){

	foreach($packets as $packet){

print "got packet $i->messagetype source {$i->fields['scalli']} dest {$i->fields['dcalli']}\n";

		if(@$packet['udp']){
			$i->load($packet['udp']['packet']);
		}

		if('new'==$i->messagetype){
			$call = CallRegister::register($i, $packet['ip']['header']['dst'], $packet['ip']['header']['src']);
		}

		if(in_array($i->messagetype, $captureTypes)){

			$call = CallRegister::retrieve($i->fields['dcalli'], $packet['ip']['header']['dst']);
			if(!$call['user']){
				print "getting call using scalli/dst\n";
				$call = CallRegister::retrieve($i->fields['scalli'], $packet['ip']['header']['dst']);
			}
			if(!$call['user']){
				print "getting call using scalli/src\n";
				$call = CallRegister::retrieve($i->fields['scalli'], $packet['ip']['header']['src']);
			}

			if($call['user']) print
				"INSERT INTO call_packets SET \n".
				" number='{$call['dst']}', \n".
				" user='{$call['user']}', \n".
				" server=inet_aton('{$packet['ip']['header']['dst']}'), \n".
				" source=inet_aton('{$packet['ip']['header']['src']}'), \n".
				" type='{$i->messagetype}', \n".
				" time='".date('Y-m-d H:i:s',strtotime($packet['capture_packet']['time']))."', \n".
				" packet=unhex('".bin2hex($packet['packet'])."');\n\n";
		}

		if('hangup'==$i->messagetype){
			CallRegister::unregister($i, $packet['ip']['header']['dst'], $packet['ip']['header']['src']);
		}
	}
}

?>
