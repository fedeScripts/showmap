# Showmap

### Help menu

	   __ _                                         
	  / _\ |__   _____      ___ __ ___   __ _ _ __  
	  \ \| '_ \ / _ \ \ /\ / / '_ ` _ \ / _` | '_ \ 
	  _\ \ | | | (_) \ V  V /| | | | | | (_| | |_) |
	  \__/_| |_|\___/ \_/\_/ |_| |_| |_|\__,_| .__/ 
	                                         |_|    
	
	  Showmap parse the xml files obtained with Nmap generates a summary and more.
	
		Developed by fede947
		https://github.com/fede947/showmap
		Version: 1.1
	
	
	  Options:
		-host	Print host summary. By default.
		-vuln	Print vuln summary.
		-ip	Print ip/port list
		-u	Print http url list
		-csv	Create a csv file
		-S	Print services using filters.
		-help	Show this help menu.
		-nse	Search NSE script for Nmap
	
	  Usage:
		showmap  nmap.xml
		showmap -host nmap.xml
		showmap -S http	nmap.xml
		showmap -csv path/file nmap.xml




