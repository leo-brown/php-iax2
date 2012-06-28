<?php


/*
 * @desc   Decodes UDP packets from raw libpcap + ethernet II + IP block
 * @author Leo Brown
 *
 */
Class UDP_Decode{

	var $file;
	var $currentHeader=null;
	var $bufferLen=1024;
	var $packets=array();

	var $remaining='';
	var $capture=false;

	function __construct($cap){
		$this->file=fopen($cap,'rb');
	}

	function getPackets($limit=null){

		$packet_count=0;
		while( $packet = $this->getPacket() ){
			$this->packets[]=$packet;
			if($limit && $packet_count==$limit) break;
			$packet_count++;
		}
		return $this->packets;
	}

	/*
	 *  @desc Read from open file til achieve packet, if is ethernet, decode, and return
	 *
	 */
	function getPacket(){

		$data=array();
		while (!feof($this->file) || $this->remaining) {

			// read some data, appending and clearing remaining
			$buffer = $this->remaining . fread($this->file, $this->bufferLen);
			$this->remaining='';

			// save capture header
			if(!$this->capture){
				$this->capture=$this->stripCapture($buffer);
			}

			$data['capture_packet']=$this->stripCapturePacket($buffer);
			$data['capture_packet']['time']=date('Y-m-d H:i:s',$data['capture_packet']['time']);

			// strip eth packet
			if(strlen($buffer) < $data['capture_packet']['length']){
				$this->remaining=$buffer;
				continue;
			}
			else{
				// get ethernet frame and move buffer to remaining
				$ethernet = substr($buffer, 0,$data['capture_packet']['length'] );
				$this->remaining = substr($buffer, $data['capture_packet']['length']);

				// save whole raw packet
				$data['packet'] = $data['capture_packet']['raw'].$ethernet;

				// incorporate decoded ethernet
				$this->decodeEthernetFrame($ethernet, $data);
				return $data;
			}
		}
	}


	// get ethernet frame
	function stripEthernet(&$data){

		$eth  = substr($data, 0,14);
		$data = substr($data, 14);

		switch(bin2hex(substr($eth,-2))){
			case '0800': $protocol='ip'; break;
			default:     $protocol=null;
		}

		$result=array(
			'raw'=>$eth,
			'protocol'=>$protocol
		);

		return $result;
	}

	// get capture header
	function stripCapture(&$data){
		$capdata  = substr($data, 0,24);
		$data = substr($data,24);
		return array(
			'raw'=>$capdata
		);
	}

	// get capture packet header
	function stripCapturePacket(&$data){
		$capdata  = substr($data, 0,16);
		$data = substr($data,16);

		return array(
			'raw'   =>$capdata,
			'length'=>@reset(unpack('S',(substr($capdata,8,2)))),
			'time'  =>@reset(unpack('L',(substr($capdata,0,4))))
		);
	}

	// get ethernet frame
	function stripIP(&$data){

		$result=array();

		// get header len (stored in 32 bit multiples)
		$len = ord(substr($data,0,1)) & bindec('00001111');
		$result['header']['len'] = $len * 4;

		// get OVERALL packet len, not header len
		$result['packet']['len'] = hexdec(bin2hex(substr($data,2,2)));
		$result['packet']['len'] = $result['packet']['len'] - $result['header']['len'];

		// get IP data
		$result['header']['src']=$this->ip_convert(substr($data,12,4));
		$result['header']['dst']=$this->ip_convert(substr($data,16,4));

		// set packet data
		$result['packet']['data']=substr(
			$data,
			$result['header']['len'],
			$result['packet']['len']
		);

		// get proto
		switch($p=ord(substr($data,9,1))){
			case 0x06: $proto='tcp'; break;
			case 0x11: $proto='udp'; break;
			case 0x5c: $proto='mcast'; break;
			default:
				print "Do not know protocol number $p\n Data:" . print_r( $result,1 ) . "\n Packet:". bin2hex(substr($data,0,50));
				$proto=null;
		}
		$result['packet']['protocol']=$proto;

		$data = substr($data, $result['header']['len']);

		return $result;

	}

	function ip_convert($ip){

		$hex     = bin2hex($ip);
		$numeric = hexdec($hex);
		return long2ip($numeric);
		
	}

	// get ethernet frame
	function stripUDP(&$data){
		$result=array();
		$result['header']['raw']=substr($data,0,8);
		$data=substr($data,8);
		return $result;
	}

	// get ethernet frame
	function stripTCP(&$data){
		$result=array();
		$result['header']['raw']=substr($data,0,20);
		$data=substr($data,20);
		return $result;
	}

	function __deconstruct(){
		fclose($this->file);
	}


	function decodeEthernetFrame($buffer, &$data){

		$data['ethernet']=$this->stripEthernet($buffer);

		if($data['ethernet']['protocol']!='ip'){
			print("Read non-IP traffic\n");
		}

		$data['ip']=$this->stripIP($buffer);


		// udp/tcp decode
		if($data['ip']['packet']['protocol']=='udp' && !@$data['udp']){
			$data['udp']['header']['raw']=$this->stripUDP($buffer);

			$data['udp']['packet']=substr($buffer, 0, $data['ip']['packet']['len'] -8);
		}
		elseif($data['ip']['packet']['protocol']=='tcp' && !@$data['tcp']){
			$data['tcp']['header']['raw']=$this->stripTCP($buffer);
			$data['tcp']['packet']=substr($buffer, 0, $data['ip']['packet']['len']);
		}

	}

}

?>
