<pre>
<?php

require('Classes/udp_decode.class.php');
require('Classes/iax_decode.class.php');
require('Classes/call_register.class.php');

CallRegister::$servers=array(
	'/127.0.0.1/',
	'/127.0.0.[0-9]{1,3}/'
);

/*
	CREATE TABLE call_log(
		id mediumint unsigned not null auto_increment primary key,
		number char(16),
		user char(32),
		server char(12),
		source char(12),
		ended char(12),
		server char(12),
		time datetime,
		clear_code char(32)
	);
*/

if(!file_exists('capture.hex')) die();

$t = new TCPDUMP_UDP_Decode('capture.hex');
$i = new IAX_Decode();

$blocks = $t->getBlocks();

foreach($blocks as $block){

	$i->load($block['data']);

	switch($i->messagetype){

		case 'new':

			CallRegister::register($i, $block['header']['dst']['ip'], $block['header']['src']['ip']);

		break;


		case 'hangup':

			$call = CallRegister::retrieve($i->fields['scalli'], $block['header']['dst']['ip']);

			if($call['user']) print
				"INSERT INTO call_log SET \n".
				" number='{$call['dst']}', \n".
				" user='{$call['user']}', \n".
				" server='{$call['server']}', \n".
				" source='{$call['source']}', \n".
				" ended='{$call['ended']}', \n".
				" time='".date('Y-m-d H:i:s',strtotime($block['header']['time']))."', \n".
				" clear_code='{$i->data['hangup_cause']}';\n\n";

			CallRegister::unregister($i, $block['header']['dst']['ip'], $block['header']['src']['ip']);

		break;

		case 'accept':
			
		break;
	}
}

?>
