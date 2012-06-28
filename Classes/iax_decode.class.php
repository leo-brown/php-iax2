<?php


/*
 * @desc   Decodes IAX payloads into Object storage
 * @author Leo Brown
 *
 */
Class IAX_Decode{

	var $subclass=false;
	var $fields=array();
	var $messagetype=false;

	var $data=array();
	var $debug=false;

	const FRAME_DTMF        = 0x01;
	const FRAME_CONTROL     = 0x04;
	const FRAME_IAX2        = 0x06;

	const IAX2CLASS_NEW      = 0x01;
	const IAX2CLASS_PING     = 0x02;
	const IAX2CLASS_PONG     = 0x03;
	const IAX2CLASS_ACK      = 0x04;
	const IAX2CLASS_HANGUP   = 0x05;
	const IAX2CLASS_REJECT   = 0x06;
	const IAX2CLASS_ACCEPT   = 0x07;
	const IAX2CLASS_AUTHREQ  = 0x08;
	const IAX2CLASS_AUTHREP  = 0x09;
	const IAX2CLASS_INVAL    = 0x0A;
	const IAX2CLASS_LAGRQ    = 0x0B;
	const IAX2CLASS_LAGRP    = 0x0C;
	const IAX2CLASS_REGISTER = 0x0D;
	const IAX2CLASS_REGAUTH  = 0x0E;
	const IAX2CLASS_REGACK   = 0x0F;

	const CONTROL_HANGUP     = 0x01;
	const CONTROL_RINGING    = 0x03;
	const CONTROL_ANSWER     = 0x04;
	const CONTROL_BUSY       = 0x05;
	const CONTROL_CONGESTION = 0x08;
	const CONTROL_FLASH      = 0x09;
	const CONTROL_PROGRESS   = 0x0e;
	const CONTROL_PROCEEDING = 0x0f;
	const CONTROL_HOLD       = 0x10;
	const CONTROL_UNHOLD     = 0x11;
	const CONTROL_STOPSOUNDS = 0xFF;

	const CODEC_G723_1	= 0x00000001;
	const CODEC_GSM_FULL	= 0x00000002;
	const CODEC_G711_U	= 0x00000004;
	const CODEC_G711_A	= 0x00000008;
	const CODEC_G726	= 0x00000010;
	const CODEC_IMA_ADPCM	= 0x00000020;
	const CODEC_16BIT_LE	= 0x00000040;
	const CODEC_LPC10	= 0x00000080;
	const CODEC_G729	= 0x00000100;
	const CODEC_SPEEX	= 0x00000200;
	const CODEC_ILBC	= 0x00000400;
	const CODEC_G726_AAL2	= 0x00000800;
	const CODEC_G722	= 0x00001000;
	const CODEC_AMR		= 0x00002000;
	const CODEC_JPEG	= 0x00010000;
	const CODEC_PNG		= 0x00020000;
	const CODEC_H261	= 0x00040000;
	const CODEC_H263	= 0x00080000;
	const CODEC_H263P	= 0x00100000;
	const CODEC_H264	= 0x00200000;

	function __construct(){
	}

	/*
	 *
	 * @author Leo Brown
	 * @desc   Take IAX frame and absorb all relevant data
	 *
	 */
	function load($data){

		$this->data=array();
		if ($this->isFullFrame($data)){

			// little bit over the top, but left in for clarity
			// need to xor the hex of source call id, as only 15 bit integer
			$sourceCallBinary = substr($data,0,2);
			$sourceCallHex    = bin2hex($sourceCallBinary) xor 32768;
			$sourceCall       = base_convert($sourceCallHex,16,10);

			$this->fields['scalli']=$sourceCall;
			$this->fields['dcalli']=ord(substr($data,3,1));
			$this->fields['tstamp']=bin2hex(substr($data,5,3));
			$this->fields['oseqid']=ord(substr($data,8,1));
			$this->fields['iseqid']=ord(substr($data,9,1));
			$this->fields['f_type']=ord(substr($data,10,1));
			$this->fields['sclass']=ord(substr($data,11,1));

			$this->decodeFullFrame($data);

		}
		else{
			$this->messagetype='voice';
		}

	}

	/*
	 *
	 * @author Leo Brown
	 * @desc   Determines if frame is a full frame
	 *
	 */
	function isFullFrame($data){
		return ord(substr($data,0,1)) & bindec('10000000');
	}


	/*
	 *
	 * @author Leo Brown
	 * @desc   Decodes a full frame by frame subtype
	 *
	 */
	function decodeFullFrame($data){

		switch($this->fields['f_type']){
			case IAX_Decode::FRAME_IAX2:		$this->decodeIAX2Frame($data);	break;
			case IAX_Decode::FRAME_CONTROL:		$this->decodeControlFrame($data); break;

// voice
//			default: print_r($this->fields); break;
		}

	}


	/*
	 *
	 * @author Leo Brown
	 * @desc   Determines control subclass and derives IAX info accordingly
	 *
	 */
	function iaxInfo($pkt){

		$info=array();

		for($n=0;$n<strlen($pkt);$n++){

			// get type and $len
			$type = $this->iaxInfoType(substr($pkt,$n,1));
			$len  = ord(substr($pkt,++$n,1));
			$data = substr($pkt,++$n,$len);

			$info[$type] = $data;

			// move data pointer forward
			$n += $len-1;

		}

		return $info;
	}

	/*
	 *
	 * @author Leo Brown
	 * @desc   Determine IAX2 Frame "Element Info" items on the basis of EI block, and return
	 *
	 */
	function iaxInfoType($code){

		switch(ord($code)){
			case 0x01: return 'called_number';
			case 0x02: return 'calling_number';
			case 0x04: return 'caller_name';
			case 0x06: return 'auth_user';
			case 0x08: return 'codec_capability';
			case 0x09: return 'desired_codec';
			case 0x0a: return 'desired_language';
			case 0x0b: return 'protocol_version';
			case 0x0c: return 'adsi_capability';
			case 0x0e: return 'auth_methods';
			case 0x0f: return 'challenge_data';
			case 0x10: return 'challenge_result';
			case 0x13: return 'register_timeout';
			case 0x1f: return 'date_time';
			case 0x26: return 'calling_presentation';
			case 0x27: return 'calling_type';
			case 0x28: return 'calling_transit';
			case 0x2a: return 'hangup_cause';
			case 0x2d: return 'codec_prefs';
		}

	}

	/*
	 *
	 * @author Leo Brown
	 * @desc   
	 *
	 */
	function decodeCodec($codecMask){

		$codecs=array();

		if(IAX_Decode::CODEC_G723_1    &$codecMask) $codecs[]='g723.1';
		if(IAX_Decode::CODEC_GSM_FULL  &$codecMask) $codecs[]='gsm';
		if(IAX_Decode::CODEC_G711_U    &$codecMask) $codecs[]='g711_u';
		if(IAX_Decode::CODEC_G711_A    &$codecMask) $codecs[]='g711_a';
		if(IAX_Decode::CODEC_G726      &$codecMask) $codecs[]='g726';
		if(IAX_Decode::CODEC_IMA_ADPCM &$codecMask) $codecs[]='ima_adpcm';
		if(IAX_Decode::CODEC_16BIT_LE  &$codecMask) $codecs[]='16bit_le';
		if(IAX_Decode::CODEC_LPC10     &$codecMask) $codecs[]='lpc10';
		if(IAX_Decode::CODEC_G729      &$codecMask) $codecs[]='g729';
		if(IAX_Decode::CODEC_SPEEX     &$codecMask) $codecs[]='speex';
		if(IAX_Decode::CODEC_ILBC      &$codecMask) $codecs[]='ilbc';
		if(IAX_Decode::CODEC_G726_AAL2 &$codecMask) $codecs[]='g726_aal2';
		if(IAX_Decode::CODEC_G722      &$codecMask) $codecs[]='g722';
		if(IAX_Decode::CODEC_AMR       &$codecMask) $codecs[]='amr';
		if(IAX_Decode::CODEC_JPEG      &$codecMask) $codecs[]='jpeg';
		if(IAX_Decode::CODEC_PNG       &$codecMask) $codecs[]='png';
		if(IAX_Decode::CODEC_H261      &$codecMask) $codecs[]='h261';
		if(IAX_Decode::CODEC_H263      &$codecMask) $codecs[]='h263';
		if(IAX_Decode::CODEC_H263P     &$codecMask) $codecs[]='h263p';
		if(IAX_Decode::CODEC_H264      &$codecMask) $codecs[]='h264';

		return $codecs;
	}

	/*
	 *
	 * @author Leo Brown
	 * @desc   Determines IAX2 subclass and derives IAX info accordingly
	 *
	 */
	function decodeControlFrame($data){

		$this->messagetype='';
		switch(bin2hex(substr($data,-1))){
			case IAX_Decode::CONTROL_HANGUP:     $this->messagetype='hangup'; break;
			case IAX_Decode::CONTROL_RINGING:    $this->messagetype='ringing'; break;
			case IAX_Decode::CONTROL_ANSWER:     $this->messagetype='answer'; break;
			case IAX_Decode::CONTROL_BUSY:       $this->messagetype='busy'; break;
			case IAX_Decode::CONTROL_CONGESTION: $this->messagetype='congestion'; break;
			case IAX_Decode::CONTROL_FLASH:      $this->messagetype='flash'; break;
			case IAX_Decode::CONTROL_PROGRESS:   $this->messagetype='progress'; break;
			case IAX_Decode::CONTROL_PROCEEDING: $this->messagetype='proceeding'; break;
			case IAX_Decode::CONTROL_HOLD:       $this->messagetype='hold'; break;
			case IAX_Decode::CONTROL_UNHOLD:     $this->messagetype='unhold'; break;
			case IAX_Decode::CONTROL_STOPSOUNDS: $this->messagetype='stopsounds'; break;
			// default: print_r(ord(substr($data,-1))); break;
		}
		return;
	}

	/*
	 *
	 * @author Leo Brown
	 * @desc   Determines IAX2 subclass and derives IAX info accordingly
	 *
	 */
	function decodeIAX2Frame($data){

		$this->data = $this->iaxInfo(substr($data,12));

		switch($this->fields['sclass']){

			case IAX_Decode::IAX2CLASS_ACK:      $this->messagetype='acknowledge';		break;
			case IAX_Decode::IAX2CLASS_LAGRQ:    $this->messagetype='lag_request';		break;
			case IAX_Decode::IAX2CLASS_PONG:     $this->messagetype='ping_response';		break;
			case IAX_Decode::IAX2CLASS_AUTHREQ:  $this->messagetype='auth_challenge';	break;
			case IAX_Decode::IAX2CLASS_REJECT:   $this->messagetype='reject';		break;
			case IAX_Decode::IAX2CLASS_AUTHREP:  $this->messagetype='auth_response';		break;

			case IAX_Decode::IAX2CLASS_ACCEPT:
				$this->messagetype='accept';
				$this->data['desired_codec'] = $this->decodeCodec(ord($this->data['desired_codec']));
			break;

			case IAX_Decode::IAX2CLASS_NEW:      $this->messagetype='new';
				$this->data['codec_prefs']      = $this->decodeCodec(ord(@$this->data['codec_prefs']));
				$this->data['desired_codec']    = $this->decodeCodec(ord(@$this->data['desired_codec']));
				$this->data['codec_capability'] = $this->decodeCodec(ord(@$this->data['codec_capability']));
			break;

			case IAX_Decode::IAX2CLASS_REGISTER: $this->messagetype='register_attempt';
				$this->data['register_timeout']=ord(substr($this->data['register_timeout'],1));
			break;

			case IAX_Decode::IAX2CLASS_REGACK:   $this->messagetype='register_accept';
				$this->data['register_timeout']=ord(substr($this->data['register_timeout'],1));
			break;

			case IAX_Decode::IAX2CLASS_HANGUP:
				$this->messagetype='hangup';
				switch(ord($this->data['hangup_cause'])){
					case 0: $this->data['hangup_cause']='unspecified'; break;
					case 1: $this->data['hangup_cause']='unassigned_number'; break;
					case 2:
					case 3: $this->data['hangup_cause']='no_route'; break;
					case 16: $this->data['hangup_cause']='normal_clearing'; break;
					case 17: $this->data['hangup_cause']='busy'; break;
					case 21: $this->data['hangup_cause']='rejected'; break;
					case 27: $this->data['hangup_cause']='destination_fault'; break;
					case 28: $this->data['hangup_cause']='invalid_number'; break;
					case 38: $this->data['hangup_cause']='network_fault'; break;
//					default: print_r(ord($this->data['hangup_cause'])); die();
				}
			break;

			default:
				if($this->debug){
					print_r($this->data);
					var_dump( bin2hex($data) );
					print "\n\n";

					foreach($this->fields as $name=>$v){
						print "$name = ".bin2hex($v)."\n";
					}
					print "\n\n";
				}
				$this->messagetype=false;
			break;

		}
	}

}

?>
