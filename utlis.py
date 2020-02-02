import pycountry
import requests

def getprov():
    country = pycountry.subdivisions.get(country_code="ID")
    location = [prov.name for prov in country]
    return location


def getallphyto():
    try:
        r = requests.get("https://server1.inpel.id:888/phyto")
        d = r.json()
    except:
        print("Max retry!")
        d = {}

    phyto = {}
    for i in range(len(d)):
        if d[i]["name"] not in phyto:
            phyto[d[i]["name"]] = [d[i]["_id"]]
        else:
            phyto[d[i]["name"]].append(d[i]["_id"])

    return phyto