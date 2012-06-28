<?php


/*
 * @desc   Decodes UDP packets from TCPDUMP in -xen format.
 * @author Leo Brown
 *
 */
Class TCPDUMP_UDP_Decode{

	var $file;
	var $currentHeader=null;
	var $bufferLen=8192;

	function __construct($cap){
		$this->file=fopen($cap,'r');
	}

	function getBlocks(){

		$blocks=array();
		while( $block = $this->getBlock() ){
			$blocks[]=$block;
		}
		return $blocks;
	}

	function getBlock(){

		$data=array();

		if (!feof($this->file)) while (!feof($this->file)) {

			$thisHeader = $this->currentHeader;
			$line = trim(fgets($this->file, $this->bufferLen));

			// if is header, store
			if($this->is_header( $line )){

				// if no header, store this and continue
				if(!$this->currentHeader ){
					$this->currentHeader=$line;
					continue;
				}

				// if current header, this is a new block - come back
				else{
					$this->currentHeader=$line;
					break;
				}
			}

			// if is 
			elseif($this->is_data($line)){
				$data[]=$line;
			}
		}

		else return false;

		$header = $this->headerDecode( $thisHeader );
		$data   = $this->udpPayload( $this->binify($data), $header );

		return array(
			'header'=>$header,
			'data'=>$data
		);

	}

	function headerDecode($header){

		$data=array();

		// time
		preg_match('/^([0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}) /',$header,$time);
		$data['time']=@$time[1];

		// IPs
		preg_match_all('/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,5}[: ]/',$header,$ips);
		$data['dst']['ip']=@$ips[1][0];
		$data['src']['ip']=@$ips[1][1];

		// MACs
		preg_match_all('/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})[ ,]/',$header,$macs);
		$data['dst']['mac']=@$macs[1][0];
		$data['src']['mac']=@$macs[1][1];

		// MACs
		preg_match_all('/length ([0-9]*)/',$header,$lens);
		$data['size']['ip4']=@$lens[1][0];
		$data['size']['udp']=@$lens[1][1];

		return $data;

	}

	// take human-readable hex and convert to binary
	function binify($data){

		$result='';
		foreach($data as $d){
			$m=array();
			preg_match('/0x[0-9]{4}:  (.*)/',$d,$m);
			$result.=@$m[1];
		}
		$result = str_replace(' ','',$result);
		$result = @pack('H*',$result);
		return $result;
	}

	// get UDP portion of message
	function udpPayload($data, $headerInfo){
		return substr($data, 28 );	
	}

	// search for 12:45:31 etc
	function is_header($line){
		return substr($line,2,1)==':';
	}

	// search for 12:45:31 etc
	function is_data($line){
		return substr($line,0,2)=='0x';
	}

	function __deconstruct(){
		fclose($this->file);
	}

}

?>
