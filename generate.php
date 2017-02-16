<?php

error_reporting(0);

$idRsa = file_get_contents(getenv('HOME') . '/.ssh/id_rsa');
$idRsaPub = file_get_contents(getenv('HOME') . '/.ssh/id_rsa.pub');
if (!$idRsa) die("Need id_rsa\n");
if (!$idRsaPub) die("Need id_rsa.pub\n");

if (!$argv[1])  echo 'Please enter passwd: ';
$pwd1 = $argv[1] ?: trim(fgets(STDIN));
if (!$argv[2]) echo 'Please enter confirm passwd: ';
$pwd2 = $argv[2] ?: trim(fgets(STDIN));

$idRsaAuthcode = authcode($idRsa, 'ENCODE', sha1($pwd1 . $pwd2));
$idRsaPubAuthcode = authcode($idRsaPub, 'ENCODE', sha1($pwd2 . $pwd1));

@file_put_contents('./id_rsa_authcode', $idRsaAuthcode);
@file_put_contents('./id_rsa_pub_authcode', $idRsaPubAuthcode);

die('Success!');

function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0)
{
    $ckey_length = 4; $key = md5($key ? $key : UC_KEY); $keya = md5(substr($key, 0, 16)); $keyb = md5(substr($key, 16, 16)); $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : ''; $cryptkey = $keya.md5($keya.$keyc); $key_length = strlen($cryptkey); $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string; $string_length = strlen($string); $result = ''; $box = range(0, 255); $rndkey = array(); for($i = 0; $i <= 255; $i++) { $rndkey[$i] = ord($cryptkey[$i % $key_length]); } for($j = $i = 0; $i < 256; $i++) { $j = ($j + $box[$i] + $rndkey[$i]) % 256; $tmp = $box[$i]; $box[$i] = $box[$j]; $box[$j] = $tmp; } for($a = $j = $i = 0; $i < $string_length; $i++) { $a = ($a + 1) % 256; $j = ($j + $box[$a]) % 256; $tmp = $box[$a]; $box[$a] = $box[$j]; $box[$j] = $tmp; $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256])); } if($operation == 'DECODE') { if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) { return substr($result, 26); } else { return substr($result, 26); } } else { return $keyc.str_replace('=', '', base64_encode($result)); }
}
