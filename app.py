from flask import Flask, render_template, request, flash, url_for, redirect, session, jsonify
from werkzeug.datastructures import ImmutableMultiDict
import pycountry
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'KJSAksd12321jndsaASKANDSK1iwnemasd'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB

application = app
back_url = ''

@app.route(f'{back_url}/')
def landing():
    if 'login' not in session:
        login = False
    else:
        login = session['login']

    try:
        r = requests.get('https://server1.inpel.id:888/phyto')
        d = r.json()
    except:
        print('Max retry!')
        d = {}

    country = pycountry.subdivisions.get(country_code='ID')
    location = [prov.name for prov in country]

    phyto = []
    for i in range(len(d)):
        sama = False
        for j in phyto:
            if d[i]['name'] in j:
                sama = True
        if not sama:
            phyto.append([d[i]['name'],d[i]['_id']])

    return render_template('landing.html', login=login,location=location, phyto=phyto)

@app.route(f'{back_url}/query')
def query():
    login = ''
    if 'login' not in session:
        login = False
    else:
        login = session['login']

    # GET PROVINCE LIST
    country = pycountry.subdivisions.get(country_code='ID')
    location = [prov.name for prov in country]

    # GETTING ARGS
    args = {}
    args = {
        "query":request.args.get('query'),
        "filterby":request.args.get('filterby'),
        "location":request.args.get('location'),
        "phyto":request.args.get('phyto')
    }

    argslist = list(args.values())

    # GETTING PHYTO LIST
    try:
        r = requests.get('https://server1.inpel.id:888/phyto')
        d = r.json()
    except:
        print('Max retry!')
        d = {}

    # REMOVE DUPLICATE PHYTOCHEMS
    phyto = []
    for i in range(len(d)):
        sama = False
        for j in phyto:
            if d[i]['name'] in j:
                sama = True
        if not sama:
           phyto.append([d[i]['name'],d[i]['_id']])


    phytolist = []
    for i in d:
        if args['phyto'] == None:
            phytolist.append(i['_id'])
            continue
        if i['name'] == args['phyto']:
            phytolist.append(i['_id'])

    items = []
    if args['query'].strip():
        try:
            r = requests.get(f'https://server1.inpel.id:888/species/search/{args["query"]}')
            d = r.json()
        except:
            d = {}

        if d:
            items = d['hits']['hits']
        for i in range(len(items)):
            if None in items:
                items.remove(None)
    else:
        try:
            r = requests.get('https://server1.inpel.id:888/species')
            d = r.json()
            items = d
        except:
            print('Max retry!')
            items = {}

    hits = []
    if items:
        for i in items:
            if i['phytochemicalContent'] in phytolist:
                if args['location'] == None:
                    pass
                elif i['province'] not in args['location']:
                    continue
                hits.append(i)

    return render_template('query.html',login=login, argslist=argslist, hits=hits, location=location, phyto=phyto, back_url=back_url)

@app.route(f'{back_url}/query/species/<id>')
def getSpecies(id):
    return render_template('species.html', id=id)

@app.route(f'{back_url}/dashboard', methods=['GET','POST'])
def dash():
    # LOGIN STUFF
    login = ''
    if 'login' not in session:
        login = False
    else:
        login = session['login']

    if not login:
        return redirect(url_for('index'))

    # GET USER DATA
    headers = {
        "Authorization": session['token']
    }

    try:
        r = requests.get("https://server1.inpel.id:888/users/verify", headers=headers)
        d = r.json()
    except:
        print('Max retry!')
        redirect(url_for('landing'))

    params = d

    # GET USER ORGS
    try:
        r2 = requests.get("https://server1.inpel.id:888/species")
        d2 = r2.json()
    except:
        print('Max retry!')
        d2 = {}

    hits = []
    for item in d2:
        if item['owner'] == params['_id']:
            hits.append(item)

    # GET PROVINCE LIST
    country = pycountry.subdivisions.get(country_code='ID')
    location = [prov.name for prov in country]

    if request.method == 'POST':
        file_form = request.files
        d = request.form
        dso = d.to_dict(flat=False)
        param = {k: dso[k][0] if len(dso[k]) <= 1 else dso[k] for k in dso}

        param['antioxidantActivity'] = 'ada'
        param['antibacterialActivity'] = 'ada'
        param['anticancerActivity'] = 'ada'
        param['structureElucidation'] = 'ada'

        raw_image = file_form['species_image']

        img_payload = {
            'speciesImage': (raw_image.filename, raw_image.read(), "multipart/form-data")
        }

        pas = True
        for item in param.items():
            if not item[1]:
                pas = False

        if pas:
            r  = requests.post('https://server1.inpel.id:888/species', headers=headers, data=param)
            d = r.json()

            if d['success']:
                r2 = requests.post(f'https://server1.inpel.id:888/species/uploadImage/{d["id"]}', headers=headers, files=img_payload)
                d2 = r2.text

                flash('success')
        else:
            flash('Fill all of the params!')
            return redirect(url_for('dash'))

    return render_template('panel.html', login=login, params=params, hits=hits, location=location, back_url=back_url)

@app.route(f'{back_url}/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        payload = {'username':f'{username}','password':f'{password}'}
        try:
            r = requests.post('https://server1.inpel.id:888/users/authenticate', data=payload)
            d = r.json()
        except:
            d = {}

        if d['success']:
            session['token'] = d['token']
            session['login'] = True
            return redirect(url_for('landing'))
        else:
            flash('Wrong credentials, please check your password and username!')
            return redirect(url_for('login'))

    if 'login' in session and session['login'] == True:
        return redirect(url_for('landing'))

    return(render_template('login.html', back_url=back_url))

@app.route(f'{back_url}/logout')
def logout():
    if 'token' in session:
        session.pop('token')
        session['login'] = False

    return redirect(url_for('landing'))

if __name__ == '__main__':
    app.run(debug=True)