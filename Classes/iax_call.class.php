<?php
Class IaxCall{

	var $callno    = 0;
	var $callno_far= 0;
	var $timestamp = 0;
	var $seq_in    = 0;
	var $seq_out   = 0;

	var $host_near=4569;
	var $host_far;
	var $port_near;
	var $port_far=4569;

	var $user;
	var $pass;

	var $lasterror=array();

	private $socket;

	const FRAME_CONTROL             ='06';
	const SUBCLASS_CONTROL_NEW      ='01';
	const SUBCLASS_CONTROL_ACK      ='04';
	const SUBCLASS_CONTROL_POKE     ='1e';
	const SUBCLASS_CONTROL_HANGUP   ='05';
	const SUBCLASS_CONTROL_AUTHREP  ='09';
	const SUBCLASS_CONTROL_TRANSFER ='22';
	const SUBCLASS_CONTROL_LAGRP    ='0c';

	const IE_PROTOCOL_VERSION   ='0b';
	const IE_CALLER_NUMBER      ='02';
	const IE_CALLED_NUMBER      ='01';
	const IE_AUTH_USER          ='06';
	const IE_MD5_RESULT         ='10';
	const IE_CODEC_PREFS        ='2D';
	const IE_CALL_PRESENTATION  ='26';
	const IE_CALLING_TYPE       ='27';
	const IE_TRANSIT_NETWORK    ='28';
	const IE_DESIRED_LANGUAGE   ='0a';
	const IE_DESIRED_CODEC      ='09';
	const IE_CODEC_CAPABILITY   ='08';
	const IE_CPE_ADSI           ='0c';
	const IE_DATE_TIME          ='1f';


	const IE_DEFAULT_VERSION    ='0002';

	function __construct($host, $port=4569, $user='', $pass=''){
		$this->host_far=$host;
		$this->port_far=$port;
		$this->user=$user;
		$this->pass=$pass;

		$this->callno=rand(10,200);
	}


	function prepareFrame(&$frame, $type){

		$frame= pack('H*',
			'80'.
			$this->decHex($this->callno).
			$this->decHex($this->callno_far,4).
			'000000'.
			$this->decHex($this->timestamp).
			$this->decHex($this->seq_out).
			$this->decHex($this->seq_in).
			$type.
			$frame
		);
	}

	function bind($timeout=0.5){
		if(!$this->socket){
			$success=$this->socket=fsockopen(
				'udp://'.
				$this->host_far,
				$this->port_far,
				$this->lasterror['number'],
				$this->lasterror['details'],
				$timeout
			);
			socket_set_timeout($this->socket, $timeout);
			return $success;
		}
		else return true;
	}

	function sendFrame($frame, $type=IaxCall::FRAME_CONTROL, $timeout=2){
		$this->bind($timeout);

		$this->prepareFrame($frame, $type);

		fwrite($this->socket,$frame);

		$this->seq_out++;
		$this->timestamp++;

		return $this->result();
	}

	function result(){
		$result = fread($this->socket, 2048);
		return $result;
	}

	function decHex($dec,$bytes=2){
		return str_pad(dechex( $dec ),$bytes,0,STR_PAD_LEFT);
	}

	function poke(){
		return $this->sendFrame( IaxCall::SUBCLASS_CONTROL_POKE );
	}

	function acknowledge($frame){

		// save counters
		$old_timestamp = $this->timestamp;
		$old_seqin = $this->seq_in;
		$old_seqout = $this->seq_out;

		$this->timestamp = $frame['tstamp'];
		$this->seq_in = $frame['oseqid'];
		$this->seq_out = $frame['iseqid'];
		$send = $this->sendFrame( IaxCall::SUBCLASS_CONTROL_ACK );

		// restore counters
		$this->timestamp = $old_timestamp;
		$this->seq_in = $old_seqin;
		$this->seq_out = $old_seqout;
	}

	function hangup(){
		return $this->sendFrame( IaxCall::SUBCLASS_CONTROL_HANGUP );
	}

	function originate($from, $to, $codecs='0000ff0e', $codec_prefs='4544434c', $desired_codec='00000008'){
		return $this->sendFrame(

			IaxCall::SUBCLASS_CONTROL_NEW.

			$this->controlInfo(IaxCall::IE_PROTOCOL_VERSION, IaxCall::IE_DEFAULT_VERSION).
			$this->controlInfo(IaxCall::IE_CALLED_NUMBER,    bin2hex($to)).
			$this->controlInfo(IaxCall::IE_CODEC_PREFS,      $codec_prefs).
			$this->controlInfo(IaxCall::IE_CALLER_NUMBER,    bin2hex($from)).
			$this->controlInfo(IaxCall::IE_CALL_PRESENTATION,'00').
			$this->controlInfo(IaxCall::IE_CALLING_TYPE,     '00').
			$this->controlInfo(IaxCall::IE_TRANSIT_NETWORK,  '0000').
			$this->controlInfo(IaxCall::IE_DESIRED_LANGUAGE, bin2hex('en')).
			$this->controlInfo(IaxCall::IE_AUTH_USER,        bin2hex($this->user)).
			$this->controlInfo(IaxCall::IE_DESIRED_CODEC,    $desired_codec).
			$this->controlInfo(IaxCall::IE_CODEC_CAPABILITY, $codecs).
			$this->controlInfo(IaxCall::IE_CPE_ADSI,         '0002').
			$this->controlInfo(IaxCall::IE_DATE_TIME,        $this->getTime())

		);
	}

	/**
	  * The data field of a DATETIME information element is four octets long
	  * Where the bit usage is shown below - the year offset is from 2000.
	  *
	  * MSB                                 LSB
	  *   yyyyyyym|mmmddddd|hhhhhmmm|mmmsssss
	  *   --------|--------|--------|--------
	  */
	function getTime(){

		function timeEncode($element,$bits,$offset=0){
			return str_pad(
				decbin(date($element)+$offset),
				$bits,
				0,
				STR_PAD_LEFT
			);
		}

		// no direct binhex (bin2hex is for real binary data)
		return dechex(bindec(
			timeEncode('Y',7,-2000).
			timeEncode('m',4).
			timeEncode('d',5).
			timeEncode('H',5).
			timeEncode('i',6).
			timeEncode('s',5)
		));
			
	}

	function transfer($to){
		return $this->sendFrame(

			IaxCall::SUBCLASS_CONTROL_TRANSFER.

			$this->controlInfo(IaxCall::IE_PROTOCOL_VERSION, IaxCall::IE_DEFAULT_VERSION).
			$this->controlInfo(IaxCall::IE_CALLED_NUMBER,    bin2hex($to))

		);
	}

	function respondLagRequest(){

		return $this->sendFrame(
			IaxCall::SUBCLASS_CONTROL_LAGRP
		);
	}

	function respondChallenge($challenge){

		$h=hash_init('md5');
		hash_update($h,$challenge);
		hash_update($h,$this->pass);
		$answer = hash_final($h);

		return $this->sendFrame(
			IaxCall::SUBCLASS_CONTROL_AUTHREP.
			$this->controlInfo(IaxCall::IE_MD5_RESULT, bin2hex($answer))
		);
	}

	function controlInfo($type, $data){

		return
			$type .
			str_pad(dechex(strlen($data)/2),2,0,STR_PAD_LEFT).
			$data;

	}

	function __deconstruct(){
		if($this->socket) fclose($this->socket);
	}

}
?>
