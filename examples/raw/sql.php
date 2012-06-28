<?php

if(!$f=@$argv[1]){
	die("Usage: extract file\n");
}

?>

<pre>
<?php

/*
CREATE TABLE call_packets(
 id int unsigned not null auto_increment primary key,
 number char(32),
 user char(32),
 server int unsigned not null,
 source int unsigned not null,
 type char(15),
 time datetime,
 packet char(255)
);

CREATE OR REPLACE VIEW _call_packets AS SELECT
 id, number, user,
 inet_ntoa(server) server,
 inet_ntoa(source) source,
 type, time, hex(packet)
 from call_packets;
;
*/

require('../../Classes/udp_decode.class.php');
require('../../Classes/iax_decode.class.php');
require('../../Classes/call_register.class.php');

// for files only not streams
// if(!file_exists($f)) die();

$t = new UDP_Decode($f);
$i = new IAX_Decode();

$captureTypes = array(
	'register_attempt',
	'register_accept',
	'accept',
	'new',
	'auth_challenge',
	'auth_response',
	'hangup'
);

// batch mode
//$packets = $t->getPackets();
//foreach($packets as $packet){

// stream mode
while( $packet = $t->getPacket() ){

	if(@$packet['udp']){
		$i->load($packet['udp']['packet']);
print_r($i);

	}

	if($i->messagetype){  //!='voice' && $i->messagetype!='acknowledge'){
//		print "{$packet['capture_packet']['length']} {$i->messagetype} \n";
	}


	if('new'==$i->messagetype){
		$call = CallRegister::register($i, $packet['ip']['header']['dst'], $packet['ip']['header']['src']);
	}

	if(in_array($i->messagetype, $captureTypes)){
//	if(!is_array($captureTypes) || in_array($i->messagetype, $captureTypes)){

		$call = CallRegister::retrieve($i->fields['dcalli'], $packet['ip']['header']['dst']);

		if(!$call['user']){
			$call = CallRegister::retrieve($i->fields['scalli'], $packet['ip']['header']['dst']);
		}

		if($call['user'])  print
			"INSERT INTO call_packets SET \n".
			" number='{$call['dst']}', \n".
			" user='{$call['user']}', \n".
			" server=inet_aton('{$call['server']}'), \n".
			" source=inet_aton('{$call['source']}'), \n".
			" type='{$i->messagetype}', \n".
			" time='".date('Y-m-d H:i:s',strtotime($packet['capture_packet']['time']))."', \n".
			" packet=unhex('".bin2hex($packet['packet'])."');\n\n";
	}

	if('hangup'==$i->messagetype){
		CallRegister::unregister($i, $packet['ip']['header']['dst'], $packet['ip']['header']['src']);
	}
}

?>
