Grabber v1.0
Updated and patched some of vulnerabilities of original Grabber v0.1
------------

Grabber is a web application which try to be as useful as possible ie allows:
- back box testing
- hybrid analysis
- javscript source code checker
- Detects Vulnerabilities like XSS, SQL, Javascript, CommandLine Injection, etc.

The tool aims to be quite generic, so even if I use PHP-SAT as php source code analyzer, you could use
a java source code analyzer for your website. You can also add some attacks pattern you found etc.
For more information go to the website.

Contact
-------
  Version v0.1
  author:  Romain Gaucher
  website: http://rgaucher.info/beta/grabber
  email:   r@rgaucher.info

  version v1.0
  authors: Shivam, Savitha, Shruti, Sri Venkatesh, Hamsalekha
  email: skgarg1@asu.edu 

Changes/Enhancement in tool:
----------------------------

   + Support of cookies
   + Support for basic authentication
   + Support for authentication with CSRF token
   + Support over SSL connection
   + command line injection vulnerability detection
   + improved scanning.
   + Improved time of execution.

Disclaimer
----------

This tool was build over existing tool "Grabber" authored by Romain Gaucher. This tool was enhanced as a part of course requirement for CSE 591, Software Vulnarability Analysis Spring 2015, Arizona State University. 
This tool does not have a UI and all the reports are stored inside folder Result.
If this tool does not find any vulnerability that doesnt mean that application which it was run on is 100% vulnerability free. 

Licence
-------
Licenced under BSD.

Acknowledgement
---------------

We would like to thank Dr Adam Doupe for providing us with opportunity to design and implement vulnerability detection tool and detailed class lectures on various types of security aspects on detection and prevention of vulnerability in software. We would also like to thank Teaching Assistant, Mr Raymond Tu for his support and guidance throughout the this application.

Pre-Requisite:
-------------
   + BeautifulSoup v 3.X
   + Python 

How to Run:
-----------
   + without Http authentication:
         + python grabber.py --sql --xss --bsql --javascript --session --commandInjection --url http://www.yoururl.com

   + with basic Http authentication
         + python grabber.py --sql --xss --bsql --javascript --session --commandInjection --url http://www.yoururl.com -- auth http://www.yoururl.com/login --user <username> --pwd <password>

   + with basic Http authentication and CSRF token
         + python grabber.py --sql --xss --bsql --javascript --session --commandInjection --url http://www.yoururl.com -- auth http://www.yoururl.com/login --user <username> --pwd <password> --authWithCSRF yes

Please Note if you are executing the later two commands i.e. (basic authentication or authentication with csrf token) then you would have to change the method inside spider.py, bascially you need to replace the html entity name with corresponding name of your login form.

Currently it assumes that the input form type names are "username", "password", "_csrf_token" and "submit".
the snippet of surrent configuration is : 
   # Input parameters we are going to send
		payload = {
  		'username' : username,
   		'password' : password,
   		'submit' : 'Login',
   		'_csrf_token' : csrftoken
 	  	}

supported options:
------------------
   Option                           Help
   "-u" or "--url"                  "Adress to investigate"
   "-s" or "--sql"                  "Look for the SQL Injection"
   "-x" or "--xss"                  "Perform XSS attack"
   "-b" or "--bsql"                 "Look for blind SQL Injection"
   "-z" or "--backup"               "Look for backup files"
   "-d" or "--spider"               "Look for every files"
   "-i" or "--include"              "Perform File Insertion attacks"
   "-j" or "--javascript"           "Test the javascript code"
   "-c" or "--crystal"              "Simple crystal ball test"
   "-e" or "--session"              "Session evaluation"
   "-y" or "--commandInjection"     "command injection attack"
   "-a" or "--auth"                 "authentication"
   "-n" or "--user"                 "username"
   "-p" or "--pwd"                  "password"
   "-w" or "--authWithCSRF"         "CSRF based authentication"
		
