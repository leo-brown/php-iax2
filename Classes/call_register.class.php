<?php

Class CallRegister{

	static $dns=array();
	static $calls=array();
	static $servers=array();

	function register($call, $host1='', $host2=''){

		// determine server host
		$server=$host1;
		$host=$host2;
		foreach(CallRegister::$servers as $srv){
			if(preg_match($srv, $host1)){
				$server=$host2;
				$host=$host1;
				break;
			}
			else{
				$server=$host1;
				$host=$host2;
			}
		}

		// register call
		$callRef = CallRegister::$calls[$host1][$call->fields['scalli']]=array(
			'time'      => @$call->fields['tstamp'],
			'user'      => @$call->data['auth_user'],
			'server'    => $server,
			'ended_by'  => $host1==$host?'client':'server',
			'source'    => $host,
			'clid'      => @$call->data['calling_number'],
			'dst'       => $call->data['called_number']
		);

		return $callRef;

	}

	function challenge($call, $host1='', $challenge){
		CallRegister::$calls[$host1][$call->fields['scalli']]['challenge']=$challenge;
	}

	function challengeResponse($call, $host1='', $response){
		CallRegister::$calls[$host1][$call->fields['dcalli']]['challenge_response']=$response;
	}

	function challengeCheck($call, $host1, $pass){
		$h=hash_init('md5');
		hash_update($h,CallRegister::$calls[$host1][$call->fields['dcalli']]['challenge']);
		hash_update($h,$pass);
		return hash_final($h)==CallRegister::$calls[$host1][$call->fields['dcalli']]['challenge_response'];
	}

	function unregister($call, $host1=''){
		unset(CallRegister::$calls[$host1][$call->fields['scalli']]);
	}

	function retrieve($callid, $host1=''){
		if(! $calldata = @CallRegister::$calls[$host1][$callid]){
			return false;
		}
		else return $calldata;
	}

	/*
	 *  @author Leo Brown
	 *  @desc   Cached DNS lookup
	 */
	function dns($host){

		if(!$d=@$this->dns[$host]){
			$d=gethostbyaddr($host);
			$this->dns[$host]=$d;
		}

		return $d;
	}

}

?>
