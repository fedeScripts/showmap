# Showmap

## Importante! 
Esta herramienta fue migrada a python, revisa el nuevo proyecto en [Showmap.py](https://github.com/fedeScripts/showmap.py) 

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
		-nse	Search NSE script for Nmap
		-help	Show this help menu.
	
	  Usage:
		showmap -host report.xml
		showmap -S <filter>	report.xml
		showmap -csv <path/file> report.xml
		showmap -nse smb

