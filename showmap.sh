#!/bin/bash


version="1.0"


## xml de entrada
xml_input="${!#}"
xml_tmp="preparse.xml"
host_csv_tmp="port_temp.csv"
vuln_csv_tmp="vuln_temp.csv"


function check_xml (){
	if [ -e "$xml_input" ]; then
		check_ext=$(echo $xml_input | grep -o .xml)
		if [ "$check_ext" == ".xml" ]; then
			check_file=$(awk 'NR<3 {print }' $xml_input | grep -o nmaprun)
			if [ "$check_file" != "nmaprun" ]; then
				echo ""
				echo "  This is not an XML file created with Nmap"
				echo ""
				exit
			fi
		else
			echo ""
			echo "  This is not an XML file"
			echo ""
			exit
		fi
	else
		echo "This file does not exist"
		exit 
	fi
}


function banner (){
	echo  " __ _                                         "
	echo  "/ _\ |__   _____      ___ __ ___   __ _ _ __  "
	echo  "\ \| '_ \ / _ \ \ /\ / / '_ \` _ \ / _\` | '_ \ "
	echo  "_\ \ | | | (_) \ V  V /| | | | | | (_| | |_) |"
	echo  "\__/_| |_|\___/ \_/\_/ |_| |_| |_|\__,_| .__/ "
	echo  "                                       |_|    "

}


## Quito los saltos de linea de todos los atributos output del xml
function preparse () {
sed 's/&#xa/ /g' $xml_input | sed 's/ ;//g'  > $xml_tmp
}
## elimino el tmp
function cleanup () {
	rm -f $xml_tmp $host_csv_tmp $vuln_csv_tmp
}


## Parseo del xml
function make_host_csv () {
	preparse
	xmlstarlet sel -e utf-8 -T -t -o "Host;Status;Os;Port;Proto;Status;Service;Version" -n \
		-m //nmaprun/host/ports/port -v "concat(../../address/@addr,';',../../status/@state,';',../../os/osmatch/@name,';',	\
		@portid,';',@protocol,';',state/@state,';',service/@name,';',service/@product,' ',service/@version,' ',service/@extrainfo)" -n -b \
		-n $xml_tmp > $host_csv_tmp
}
## Parseo del xml
function make_vuln_csv () {
	preparse
	xmlstarlet sel -e utf-8 -T -t \
		-o "Host;Port/Proto;Script;Output;Overview" -n \
		-m /nmaprun/host/ports/port/script -v "concat(../../../address/@addr,' ; ',../@portid,'/',../@protocol,' ; ',@id,' ; ',@output,' ; ',table/elem[1]/text(),': ',table/elem[2]/text())" -n -b \
		-n $xml_tmp > $vuln_csv_tmp
}


## Funciones de los switches

function print_host (){
	check_xml
	make_host_csv
	echo ""
	awk 'BEGIN {printf "  %-15s%-8s%-8s%-8s%-15s%-8s\n  %-15s%-8s%-8s%-8s%-15s%-8s\n", "Host","Port","Proto","State","Service","Version", "====","====","=====","=====","=======","======="} 
		{FS = ";"} NR>1 {printf "  %-15s%-8s%-8s%-8s%-15s%-8s\n", $1,$4,$5,$6,$7,$8}' $host_csv_tmp
	cleanup
}


function print_vuln (){
	check_xml
	make_vuln_csv
	echo ""
	awk 'BEGIN {printf "  %-16s%-12s%-30s%-22s\n  %-16s%-12s%-30s%-22s\n", "Host","Port/Proto","Script","Output", "====","==========","======","======","======="}' 
	awk	'BEGIN{FS = ";"} NR>1 {printf "  %-15s%-12s%-30s%-22s\n", $1,$2,$3,$5}' $vuln_csv_tmp | grep -i "vulnerable"
	echo ""
	cleanup
}


function search (){
	check_xml
	printf "\n  %-15s%-8s%-8s%-8s%-15s%-8s\n" "Host" "Port" "Proto" "State" "Service" "Version"
	printf "  %-15s%-8s%-8s%-8s%-15s%-8s\n" "====" "====" "=====" "=====" "=======" "=======" 
	print_host | grep $param_2
	echo ""
}


function make_csv (){
	check_xml
	make_host_csv
	mv $host_csv_tmp "$param_2(host-table)".csv
	make_vuln_csv
	mv $vuln_csv_tmp "$param_2(vuln-table)".csv
	echo ""
	echo "  [+] CSV file succesfuly created."
	echo ""
}


function nlocate (){
## Developed by LucasGaleano and Macle0d part of the RTT project
## https://github.com/Macle0d/rtt/

	if [ -z "$param" ]; then
		param="$param_2"
	fi

	n=$(locate .nse | grep nmap |  grep "\b$param" | awk -F "/" '{print $NF}' | cut -d '.' -f 1 | nl)

	if [ -z "$param" ]; then
		echo -e '  [-] \e[36mscript not found \e[31m(╯`o`)╯\e[39m︵ ┻━┻'
		echo -e "
		＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿
		|\e[107m　\e[1m\e[31mdetected error　　　　　　　　　　　   　\e[0m\e[107m\e[30m[－][口][×]\e[49m\e[39m|
		|￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣|
		|　\e[36m\e[1mLayer 8 error          \e[39m\e[0m 　　　　　　　　          　|
		|　　         　　　　　　　　　　　　　　　　　　　　 |
		|　　　　              ＿＿＿＿＿　                    |
		| 　　              　|\e[107m\e[1m\e[30m  Accept  \e[39m\e[0m\e[49m| 　                  |
		|　　　              　￣￣￣￣￣　　　　            　|
		￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣
		"
	elif [ -z "$n" ]; then
		echo -e '  [-] \e[36mscript not found \e[31m(╯`o`)╯\e[39m︵ ┻━┻'
	else 
		echo "$n"
	fi
	echo ""
}


function help_menu () {
	banner
	echo ""
	echo " Showmap parse the xml files obtained with Nmap generates a summary and more."
	echo
	echo "	Developed by fede947
	https://github.com/fede947/showmap
	Version: $version"
	echo ""

	echo ""
	echo " Options:"
	echo "	-host	Print host summary. By default."
	echo "	-vuln	Print vuln summary."
	echo "	-csv	Create a csv file"
	echo "	-S	Print services using filters."
	echo "	-help	Show this help menu."
	echo "	-nse	Search NSE script for Nmap"	

	echo ""
	echo " Usage:"
	echo "	showmap  nmap.xml"
	echo "	showmap -host nmap.xml"
	echo "	showmap -S http	nmap.xml"
	echo "	showmap -csv path/file nmap.xml"
	echo ""
}


function switch_selector (){
	while [ -n "$1" ]; do
			case "$1" in
			--help) help_menu ;;
			-h) help_menu ;;
			-S) 
				search "$param_1" "$param_2"
				shift
				;;
			-host) print_host
				shift
				;;
			-vuln) print_vuln
				shift
				;;
			-csv)
				make_csv "$param_1" "$param_2"
				shift
				;;
			-nse) 
				nlocate "$param_2"
				shift
				;;
			-all)
				shift
				;;
			--)
				shift
				break
				;;
			esac
			shift
		done
}


## MAIN ##

param_1="$1"
param_2="$2"

if [ -z "$param_2" ] && [ "$param_1" != "-h" ] && [ "$param_1" != "--help" ]; then
	param="$param_1"
	nlocate "$param"
else
	switch_selector "$param_1" "$param_2"
fi

