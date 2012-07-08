<?php
// Copyright 2012 Ahmed (OneOfOne) Wahed, check COPYING for the license info.

header('Content-type: json/gzip');
header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
header("Expires: Sat, 26 Jul 1997 05:00:00 GMT"); // Date in the pas
define('AUTH', '%AUTH_HASH%');

function var_equal($var, $val, &$array, $sha1 = false) {
	if($sha1) {
		return isset($array[$var]) && sha1($array[$var]) == $val;
	} else {
		return isset($array[$var]) && $array[$var] == $val;
	}
}

function fix_path($file) { //only allow relative path from this script
	return str_replace('../', '', implode('/', explode('/', $file)));
}

function make_path($file) {
	$dir = dirname($file);
	$dir = str_replace('./', '', $dir);
	if($dir == '.' || is_dir($dir)) return true;
	@mkdir($dir, 0777, true); //
	return is_dir($dir);
}

function res($data) {
	return gzcompress(json_encode($data));
}

function die_with_error($err) {
	die(res(array('error'=>$err)));
}

$req = json_decode(gzuncompress(file_get_contents("php://input")), true);

if(!var_equal('auth', AUTH, $req, true)) {
	die_with_error('Invalid Username and/or password, auth = ' . $req['auth']);
}

if(!isset($req['action'])) {
	die_with_error('Yeehaa');
}

if($req['action'] == 'check') {
	if(!isset($req['files'])) {
		die_with_error('files must be set.');
	}
	$files = $req['files'];
	$check_data = array();
	foreach($files as $f) {
		$f = fix_path($f);
		$st = @stat($f);
		$hash = null;
		$writable = false;
		if(is_array($st)){
			$hash = sha1_file($f);
			$writable = is_writable($f);
		} else {
			$writable = is_writable(dirname($f));
		}
		$check_data[$f] = array($hash, $writable);
	}
	echo res($check_data);

} else if ($req['action'] == 'can_put') {
	if(!isset($req['files'])) {
		die_with_error('files must be set.');
	}
	$files = json_decode($req['files']);
	$check_data = array();
	echo res(array('status' => is_writable('.')));

} else if($req['action'] == 'push') {
	if(!isset($req['file']) || !isset($req['data'])) {
		die_with_error('file and data must be set');
	}

	$f = fix_path($req['file']);
	if(!make_path($f)) { //MUST have the ending / or it goes kaboom
		die_with_error("Couldn't create the file path for : $f");
	}
	file_put_contents($f, base64_decode($req['data']));
	echo res(array($req['file'] => sha1_file($f)));

} else if($req['action'] == 'pull') {
	if(!isset($req['file'])) {
		die_with_error('file must be set');
	}

	$f = fix_path($req['file']);
	if(!file_exists($f)) { //MUST have the ending / or it goes kaboom
		die_with_error("file not found : $f");
	}
	$ret = array('data' => base64_encode(file_get_contents($f)), 'hash'=>sha1_file($f));
	echo res(array($req['file'] => $ret));

} else if($req['action'] == 'commit') { //not implemented on the client yet
	if(!isset($req['files'])) {
		die_with_error('files must be set.');
	}
	//TODO do something with $req['atomic']
	$files = json_decode($req['files']);
	$ret = array('status'=>true, 'failed' => array());
	foreach($files as $file) {
		$file = fix_path($file);
		$tmp = $file . '.tmp';
		if(!file_exists($tmp)) {
			$ret['failed'][] = $file;
			$ret['status'] = false;
		} else {
			if(!rename($tmp, $file)) {
				$ret['failed'][] = $file;
				$ret['status'] = false;
			}
		}
	}
	echo res($ret);
}
?>
