<h1 align="center">Akto Burp plugin</h1>
<h4 align="center">API Inventory with Burp</h4>

Released as open source by Akto on Jan 13 2023.



https://user-images.githubusercontent.com/91306853/216748138-bba85a2f-6326-4aaf-95b0-24832e53f48d.mp4



<b>Modifications:</b>
Akto burp plugin built on top of Logger++ plugin developed by Corey Arthur and  Soroush Dalili.

*23rd Jan 2023*
1. Plugin automatically sends data to Akto. No need to send data manually.
     - Added "Send data to akto automatically" toggle in options tab to control this feature.

*12th Jan 2023*
  1. Plugin can import data from Akto.io 
     - Added "Import from Akto button" in options tab which makes an API request to fetch data.
    
*8th Jan 2023*
  1. Plugin has a right click option to send data to Akto.io
     - Added Akto Credentials menu in Options tab.
     - Modified HarExporter.java to send data to Akto when export to Akto is clicked.
 
