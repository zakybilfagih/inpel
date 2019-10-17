from flask import Flask, render_template, request, flash, url_for, redirect, session
from countryinfo import CountryInfo
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'KJSAksd12321jndsaASKANDSK1iwnemasd'

@app.route('/')
def landing():

    if 'login' not in session:
        login = False
    else:
        login = session['login']

    
    r = requests.get('https://server1.naradhipabhary.com:888/phyto')
    d = r.json()

    country = CountryInfo('Indonesia')
    countd = country.info()
    location = countd['provinces']

    phyto = []
    for i in range(len(d)):
        sama = False
        for j in phyto:
            if d[i]['name'] in j:
                sama = True
        if not sama:
            phyto.append([d[i]['name'],d[i]['_id']])
    
    return render_template('landing.html', login=login,location=location, phyto=phyto)

@app.route('/query')
def query():
    login = ''
    if 'login' not in session:
        login = False
    else:
        login = session['login']

    args = {
        "query":request.args.get('query'),
        "filterby":request.args.get('filterby'),
        "location":request.args.get('location'),
        "phyto":request.args.get('phyto')
    }

    argslist = list(args.values())

    r = requests.get('https://server1.naradhipabhary.com:888/phyto')
    d = r.json()

    phytolist = []
    for i in d:
        if args['phyto'] == None:
            for j in d:
                phytolist.append(j['_id'])
            break
        if i['name'] == args['phyto']:
            phytolist.append(i['_id'])

    items = []
    if args['query'].strip():
        r = requests.get(f'https://server1.naradhipabhary.com:888/species/search/{args["query"]}')
        d = r.json()
    
        items = d['hits']['hits']
        for i in range(len(items)):
            if None in items:
                items.remove(None)
    else:
        r = requests.get('https://server1.naradhipabhary.com:888/species')
        d = r.json()

        items = d

    hits = []
    if items:
        for i in items:
            if i['phytochemicalContent'] in phytolist:
                hits.append(i)
            
    return render_template('query.html',login=login, argslist=argslist, hits=hits)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        payload = {'username':f'{username}','password':f'{password}'}
        r = requests.post('https://server1.naradhipabhary.com:888/users/authenticate', data=payload)

        d = r.json()
        if d['success']:
            session['token'] = d['token']
            session['login'] = True
            return redirect(url_for('landing'))
        else:
            flash('Wrong credentials, please check your password and username!')
            return redirect(url_for('login'))

    if 'login' in session and session['login'] == True:
        return redirect(url_for('landing'))

    return(render_template('login.html'))

@app.route('/logout')
def logout():
    session.pop('token')
    session['login'] = False

    return redirect(url_for('landing'))


if __name__ == '__main__':
    app.run(debug=True)