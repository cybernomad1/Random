from gophish import Gophish

#Change These!
api_key = ''
server = "http://GophishIP:port"
campaignID = 0


api = Gophish(api_key, host='', verify=False)

campaign = api.campaigns.get(campaign_id=campaignID)

print("Submitted Data:")
for event in campaign.timeline:
    
    if event.message == "Submitted Data":
        time = event.time
        login = event.details['payload']['login'][0]
        password = event.details['payload']['password'][0]
        print(time + "\tLogin:" + login + "\tPassword:" + password)

print("Clicked Link")
for event in campaign.timeline:
    if event.message == "Clicked Link":
        time = event.time
        email = event.email
        print(time + "\tEmail:" + email)
