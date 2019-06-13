#!/usr/bin/env php
<?php

/**
 * PHP CGNAT MIKROTIK COM NETMAP
 *
 * @author     Diorges Rocha <diorges@gis.net.br>
 * @copyright  (C) 2019 Diorges Rocha
 *
 */

chdir(dirname($argv[0]));

$options = getopt("c:s:t:o:mh");

function _print_help(){
    $help = <<<EOF
USO:
\$nomedoscript [-cstohm] 

OPTIONS:
-c                                           IP inicial do bloco CGNAT. ex.: 100.64.100.0
-s                                           Bloco Público que será usado para fazer o netmap.
-t                                           Quantidade de regras por IP. ex.: 4, 8, 16, 32 (Máscara subrede)
-o                                           Nome do arquivo que será salvo as regras de CGNAT.
-m                                           Gera regras para Mikrotik RouterOS.
-h                                           Mostra essa ajuda.\n\n\n
EOF;

    exit($help);
}

function output($file, $line) {
    $output = fopen($file, 'a');
    fwrite($output, $line."\n");
    fclose($output);
}

if(isset($options['h'])){
    _print_help();
}

if(count($argv) < 5) {
    print("-- Quantidade de parametros inválidos.\n\n");
    _print_help();
}

$subnet = array(
    '4096'  => '/20',
    '2048'  => '/21',
    '1024'  => '/22',
    '512'   => '/23',
    '256'   => '/24',
    '128'   => '/25',
    '64'    => '/26',
    '32'    => '/27',
    '16'    => '/28',
    '8'     => '/29',
    '4'     => '/30',
    '1'     => '/32'
);

$subnet_rev = array(
    '20'  => '4096',
    '21'  => '2048',
    '22'  => '1024',
    '23'   => '512',
    '24'   => '256',
    '25'   => '128',
    '26'    => '64',
    '27'    => '32',
    '28'    => '16',
    '29'     => '8',
    '30'     => '4',
    '32'     => '1'
);

$CGNAT_IP = ip2long($options['c']);
$CGNAT_START = $options['s'];
$CGNAT_RULES = $options['t'];
$CGNAT_OUTPUT = __DIR__ . DIRECTORY_SEPARATOR . $options['o'];

if(!in_array($CGNAT_RULES, array_keys($subnet))) {
    exit("-- Quantidade de regras deve ter o tamanho de uma máscara de subrede.\n\n");
}

if(file_exists($CGNAT_OUTPUT)){
    unlink($CGNAT_OUTPUT);
}

$output_rules = array();
$output_jumps = array();
$x = 1;
if(isset($options['m'])) {
    $output_rules[] = "/ip firewall nat";
}

$rules = explode('/', $CGNAT_START);
$ports = ceil((65535-1024)/$CGNAT_RULES);
$ports_start = 1025;
$ports_end = $ports_start + $ports;

$public = explode('.', $rules[0]);
$CGNAT_IP_INICIAL = $CGNAT_IP;
$checkip = $CGNAT_IP_INICIAL;

for($i=0;$i<$CGNAT_RULES;++$i){
	
	$output_rules[] = "add action=netmap chain=CGNAT_{$public[2]}_{$public[3]}-{$rules[1]}-{$x} protocol=tcp src-address=".long2ip($CGNAT_IP)."/{$rules[1]} to-addresses={$CGNAT_START} to-ports={$ports_start}-{$ports_end}";
	$output_rules[] = "add action=netmap chain=CGNAT_{$public[2]}_{$public[3]}-{$rules[1]}-{$x} protocol=udp src-address=".long2ip($CGNAT_IP)."/{$rules[1]} to-addresses={$CGNAT_START} to-ports={$ports_start}-{$ports_end}";
	$output_rules[] = "add action=netmap chain=CGNAT_{$public[2]}_{$public[3]}-{$rules[1]}-{$x} src-address=".long2ip($CGNAT_IP)."/{$rules[1]} to-addresses={$CGNAT_START}";
	$CGNAT_IP += $subnet_rev[$rules[1]];
	
	$check = $CGNAT_IP - $CGNAT_IP_INICIAL;
	if($check>255) {
		$output_jumps[] = "add chain=srcnat src-address=".long2ip($CGNAT_IP_INICIAL)."-".long2ip($CGNAT_IP-1)." action=jump jump-target=\"CGNAT_{$public[2]}_{$public[3]}-{$rules[1]}-{$x}\"";
		$CGNAT_IP_INICIAL = $CGNAT_IP;
		++$x;
	}
	
	$ports_start = $ports_end + 1;
	if($ports_start >= 65535) {
		$ports_start = 1025;
		$ports_end = $ports_start;
	}
	
	$ports_end += $ports;
	if($ports_end > 65535){
		$ports_end = 65535;
	}
}

foreach($output_rules as $o) {
    output($CGNAT_OUTPUT, $o);
}

foreach($output_jumps as $o) {
    output($CGNAT_OUTPUT, $o);
}
