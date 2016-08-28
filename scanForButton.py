from scapy.all import *
import requests
import sqlite3

#GroupMe API arguments
bot_id='fdffbc4253fea0147e7a66903c'
post_url='https://api.groupme.com/v3/bots/post'

#connects to database, puts new message string in message_text
def update_params():
	#SQLite connection
	conn = sqlite3.connect('kfDB.db')
	c = conn.cursor()

	#get the latest msg_id sent
	c.execute("SELECT msg_id FROM msgLog WHERE timestamp= (SELECT MAX(timestamp) FROM msgLog)")

	#extract data from query
	currentID = c.fetchall()[0][0]

	#move to next message
	currentID = currentID + 1

	#get message text based on new ID
	c.execute("SELECT msgText FROM msgs WHERE id={currID}"\
						.format(currID=currentID))
	#extract text
	message_text = c.fetchall()[0][0]

	#check if text is "max" if so, reset ID to 1, and start over cycle.
	if message_text == "max":
		currentID=1
		c.execute("SELECT msgText FROM msgs WHERE id={currID}"\
						.format(currID=currentID))
		message_text = c.fetchall()[0][0]

	#now make a new entry in the msgLog table 
	c.execute("INSERT INTO msgLog (id, msg_id) VALUES (NULL, {c_id})"\
						.format(c_id=currentID))

	conn.commit()
	conn.close()
	return message_text



#code to check if packet is ARP request
def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      if pkt[ARP].hwsrc == '74:c2:46:04:6f:41': # Gatorade
        #r = requests.post(post_url, data={"bot_id" : bot_id, "text" : message_text})
        print update_params()
      elif pkt[ARP].hwsrc == '74:c2:46:f2:ca:8c': # Gillette
        print "Pushed Gillette"
      else:
        print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

#This line calls the function above, gets unlimited number of arp requests 
print sniff(prn=arp_display, filter="arp", store=0, count=0)
