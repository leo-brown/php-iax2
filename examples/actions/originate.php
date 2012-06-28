#!/usr/bin/env php
<?php

	require('../../Classes/iax_call.class.php');
	require('../../Classes/iax_decode.class.php');

	if($argc<2){
		die("Usage: originate iax://user:pass@host/from_number/to_number?caller_id\n");
	}

	// get data
	extract(parse_url($argv[1]));

	// from and to numbers
	$from_to = array_filter(split('/',$path));

	// initiate iax class
	$call  = new IaxCall($host, '4569', $user, $pass);

	// originate a call
	$response = $call->originate(
		@$query,
		reset($from_to)
	);

	// load packet response into decoder
	$i = new IAX_Decode();
	$i->load($response);

	// handle a challenge if it exists
	if($i->messagetype=='auth_challenge'){

		$call->callno_far=$i->fields['scalli'];
		$call->seq_in=$i->fields['iseqid'];

		$call->respondChallenge($i->data['challenge_data']);

		$success=true;
	}

	// wait for accept or reject
	while(!in_array($i->messagetype,array('accept','reject'))){
		$i->load($call->result());
	}

	// if call accepted, wait for answer
	if($i->messagetype=='accept'){

		// wait for a call answer signal, then transfer
		while($i->messagetype!='answer'){

			$i->load($call->result());

			// manage interim lag requests
			if($i->messagetype=='lag_request'){
				$call->respondLagRequest();
			}
		}
		$call->transfer(end($from_to));
	}

	if(!@$success)	print "Origination at $host received no response.";
	else		print "Origination at $host responded!";

?>
