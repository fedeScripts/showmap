# Showmap

### Install

Run
	./install.sh

### Help menu

		 __..                      
		(__ |_  _ .    .._ _  _.._ 
		.__)| )(_) \/\/ | | )(_][_)
		                        |  
		
	  Showmap parse the xml files obtained with Nmap, generates a summary and more.
	
		Developed by fede947
		https://github.com/fede947/showmap
		Version: 1.2
	
	
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
		showmap -host nmap.xml
		showmap -S http	nmap.xml
		showmap -csv path/file nmap.xml
		showmap -nse smb
