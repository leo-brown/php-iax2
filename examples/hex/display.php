<script>
 setTimeout("this.location=this.location.href+' '", 50000);
</script>
<pre>
<?php

require('Classes/udp_decode.class.php');
require('Classes/iax_decode.class.php');
require('Classes/call_register.class.php');

if(!file_exists('capture.hex')) die();

$t = new TCPDUMP_UDP_Decode('capture.hex');
$i = new IAX_Decode();

$blocks = $t->getBlocks();

$passwords = array(
	'127.0.0.1'=>array('test1'=>'pass1'),
	'127.0.0.2'=>array('test2'=>'pass2')
);

for($n=1;$n<=count($blocks);$n++){

	$block = $blocks[$n-1];

	$i->load($block['data']);
	$call = CallRegister::retrieve($i->fields['scalli'], $block['header']['dst']['ip']);

	$output='';

	switch($i->messagetype){

		case 'new':
			$output.= '<font color="#888822">';
			$output.= "Call {$i->fields['scalli']} Requested \t ".descConn($block['header']['src']['ip'], $block['header']['dst']['ip'])." \t";
			$output.= "AUTH ".@$i->data['auth_user']." PSTN {$i->data['calling_number']}->{$i->data['called_number']} \n";
			$output.= '</font>';

			CallRegister::register($i, $block['header']['dst']['ip'], $block['header']['src']['ip']);
		break;

		case 'progress':
			$output.= '<font color="#22ee22">';
			$output.= "Call {$i->fields['dcalli']} Progress \t ".descConn($block['header']['src']['ip'], $block['header']['dst']['ip'])." \tAUTH {$i->data['auth_user']}";
			$output.= "\n";
			$output.= '</font>';
		break;

		case 'hangup':

			if(!$call){
				$call['dst']="[unknown]";
				$call['user']="[unknown]";
			}

			$output.= '<font color="#cc4444">';
			$output.= "Call {$i->fields['scalli']} Cleardown\t ".descConn($block['header']['src']['ip'], $block['header']['dst']['ip']).
				" \tCall to {$call['dst']} from {$call['user']} cause ".$i->data['hangup_cause'];
			$output.= "\n";
			$output.= '</font>';

			CallRegister::unregister($i, $block['header']['dst']['ip'], $block['header']['src']['ip']);
		break;

		case 'accept':
			$output.= '<font color="#22aa22">';
			$output.= "Call {$i->fields['dcalli']} Acceptance \t ".descConn($block['header']['src']['ip'], $block['header']['dst']['ip'])."\t";
			$output.= "\n";
			$output.= '</font>';
		break;

		case 'auth_challenge':

			CallRegister::challenge($i, $block['header']['src']['ip'], $i->data['challenge_data']);

			$output.= '<font color="#8888aa">';
			$output.= "Authorise Challenge \t ".descConn($block['header']['src']['ip'], $block['header']['dst']['ip'])." \t";
			$output.= "Peer {$i->data['auth_user']} challenged with {$i->data['challenge_data']}\n";
			$output.= '</font>';
		break;

		case 'auth_response':

			CallRegister::challengeResponse($i, $block['header']['dst']['ip'], $i->data['challenge_result']);

			$result = CallRegister::challengeCheck($i, $block['header']['dst']['ip'],
				$passwords[$block['header']['src']['ip']][$call['user']]
			)? 'CORRECT':'INCORRECT';

			$output.= '<font color="#8888cc">';
			$output.= "Authorise Response \t ".descConn($block['header']['src']['ip'], $block['header']['dst']['ip'])." \t";
			$output.= "Peer ".$call['user']." gave $result result: {$i->data['challenge_result']}\n";
			$output.= '</font>';
		break;

		/*
		case 'register_attempt':
			$output.= '<font color="#666666">';
			$output.= "Registration REQ \t ".descConn($block['header']['src']['ip'], $block['header']['dst']['ip'])." \t";
			$output.= "Peer {$i->data['auth_user']} @ {$i->data['register_timeout']} \n";
			$output.= '</font>';
		break;

		case 'register_accept':
			$output.= '<font color="#6666cc">';
			$output.= "Registration ACK \t ".descConn($block['header']['src']['ip'], $block['header']['dst']['ip'])." \t";
			$output.= "Peer {$i->data['auth_user']} @ {$i->data['register_timeout']}\n";
			$output.= '</font>';
		break;
		*/

	}

	if($output){

		print "[".
			str_pad($n,5,0,STR_PAD_LEFT)."] ".
			date('H:i:s',strtotime($block['header']['time'])).
			"  $output";
	}

}

function descConn($ip2, $ip1){

	return str_pad($ip1,16,' ', STR_PAD_RIGHT) . '->' . str_pad($ip2,16,' ', STR_PAD_LEFT);

}

?>
