import requests
import json 
ssn = requests.Session()
ssn.cookies.update({'visit-month': 'February'})
 
reqOne = ssn.get('http://httpbin.org/cookies')
print(reqOne.text)
# prints information about "visit-month" cookie
 
#reqTwo = ssn.get('http://httpbin.org/cookies', cookies={'visit-year': '2017'})
#print(reqTwo.text)
# prints information about "visit-month" and "visit-year" cookie
 
#reqThree = ssn.get('http://httpbin.org/cookies')
#print(reqThree.text)
# prints information about "visit-month" cookie

redfishheader = {  'Content-Type': 'application/json',
                    'User-Agent': 'curl/7.54.0' }

datainput = {'Attributes':{  
      'FBO201':'CD/DVD',
      'FBO202':'USB',
      'FBO203':'Hard Disk',
      'FBO204':'Network' }
}

payload = json.dumps({'Attributes':{
			'FBO201':'Network',
			'FBO202':'Hard Disk',
			'FBO203':'USB',
			'FBO204':'CD/DVD'
			}
          })

r = requests.get('https://github.com/timeline.json')
print (r.text)
print(r.status_code)
try:
    print("Why Why Why")
    session = requests.get('https://10.76.38.64/redfish/v1/Systems/Self/Bios/SD', auth=('admin', 'cmb9.admin'), verify=False, headers=redfishheader)
    #session = requests.put('https://10.76.38.64/redfish/v1/Systems/Self/Bios/SD', auth=('admin', 'cmb9.admin'), verify=False, headers=redfishheader,data='{"Attributes":{"FBO202":"USB","FBO203":"Hard Disk","FBO204":"Network","CRCS005":"Enable","IIOS1FE":"Enable", "IPMI100":"Disabled"}}')
    #session = requests.put('https://10.76.38.64/redfish/v1/Systems/Self/Bios/SD', auth=('admin', 'cmb9.admin'), verify=False, headers=redfishheader,data=payload)
    print(session.status_code)
    print(json.loads(session.content)) 
except:
    print("Do not know why it is failed")


