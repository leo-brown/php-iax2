#!/usr/bin/env php
<?php

	require('../../Classes/iax_call.class.php');
	require('../../Classes/iax_decode.class.php');

	// host to ping
	$host    = @$argv[1];
	if(!$host) die("Usage: iaxping hostname [count] [interval (ms)]\n");

	$packets = @$argv[2]?$argv[2]:4;
	$delay   = @$argv[3]?$argv[3]:1000; //ms

	// init decoder
	$frame = new IAX_Decode();

	// ping loop
	for($n=1;$n<=$packets;$n++){

		// init, die on host res fail, etc
		$call    = new IaxCall($host);

		if(!$call) die("Cannot contact host.\n");

		$success = false;
		$time_start = microtime(true);

		// poke
		if($response = $call->poke()){
			// end timer before decode
			$time_end = microtime(true);

			$frame->load( $response );
			if($frame->messagetype=='ping_response'){
				$success=true;
			}
		}

		if(@$success){
			$time = number_format(($time_end - $time_start)*1000,1);
			print "Ping to $host took {$time}ms\n";
		}
		else{
			print "Ping to $host received no response.\n";
		}

		// destroy + end
		unset($call);

		if($n!=$packets) usleep($delay*1000);

	}


?>
