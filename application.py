from flask import Flask, render_template, url_for, request, redirect, jsonify, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from db_setup import *
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import os, random, string, datetime, json, httplib2, requests
from login_decorator import login_required

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item-Catalog-pro"

engine = create_engine('sqlite:///item_catalog.db')
Base.metadata.bind = engine
# Create session
DBSession = sessionmaker(bind=engine)
session = DBSession()

def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user


def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

@app.route('/')
@app.route('/catalog/')
def Itemcatalog():
    Categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Items).order_by(asc(Items.name))
    if 'username' not in login_session:
        return render_template('index.html', Categories=Categories, items=items)
    else:
        return render_template('catalog.html', Categories=Categories, items=items)

# add new Category
@app.route('/catalog/add_category', methods=['GET', 'POST'])
@login_required
def add_cat():
        if request.method == 'POST':
            new_cat = Category(
                name=format(request.form['name']),
                user_id=login_session['user_id'])
            print new_cat
            session.add(new_cat)
            session.commit()
            return redirect(url_for('Itemcatalog'))
        else:
            return render_template('add_cat.html')

@app.route('/catalog/<path:category_name>/items/')
def showCategory(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Items).filter_by(category=category).order_by(asc(Items.name)).all()
    print items
    count = session.query(Items).filter_by(category=category).count()
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('all_items_category.html',
                                category = category.name,
                                categories = categories,
                                items = items,
                                count = count)
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('items.html',
                                category = category.name,
                                categories = categories,
                                items = items,
                                count = count,
                                user=user)

# Edit category
@app.route('/catalog/<path:category_name>/edit', methods=['GET', 'POST'])
@login_required
def edit_cat(category_name):
    cat_edit = session.query(Category).filter_by(name=category_name).one()
    category = session.query(Category).filter_by(name=category_name).one()
    """See if the logged in user is the owner of item"""
    creator = getUserInfo(cat_edit.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != item owner redirect them
    if creator.id != login_session['user_id']:
        print ("You cannot edit this Category. This Category belongs to %s" % creator.name)
        return redirect(url_for('Itemcatalog'))
    # Post Method Form
    if request.method == 'POST':
        if request.form['name']:
            cat_edit.name = request.form['name']
            session.add(cat_edit)
            session.commit()
            print("Category item have been sucesfuly edited")
            return request(url_for('Itemcatalog'))
    else:
        return render_template('edit_category.html', categories=cat_edit,
                                   category=category)

# Delete a category
@app.route('/catalog/<path:category_name>/Delete', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    delete_cat = session.query(Category).filter_by(name=category_name).one()
    # See if the logged in user is the owner of item
    creator = getUserInfo(delete_cat.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != item owner redirect them
    if creator.id != login_session['user_id']:
        print ("You cannot delete this Category. This Category belongs to %s" % creator.name)
        return redirect(url_for('Itemcatalog'))
    if request.method =='POST':
        session.delete(delete_cat)
        session.commit()
        print('Category Successfully Deleted! '+delete_cat.name)
        return redirect(url_for('Itemcatalog'))
    else:
        return render_template('deleteCategory.html',
                                category=delete_cat)


@app.route('/catalog/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    categories = session.query(Category).all()
    if request.method == 'POST':
        new_item = Items(
            name = request.form['name'],
            desc = request.form['desc'],
            date=datetime.datetime.now(),
            category = session.query(Category).filter_by(name=request.form['category']).one(),
            user_id = login_session['user_id'])
        session.add(new_item)
        session.commit()
        return redirect(url_for('Itemcatalog'))
    else:
        return render_template('add_item.html', categories=categories)

@app.route('/catalog/<path:category_name>/<path:item_name>/')
def Item_appear(category_name, item_name):
    item_catalog = session.query(Items).filter_by(name=item_name).first()
    creator = getUserInfo(item_catalog.user_id)
    categories = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('catalog.html',
                               item_catalog=item_catalog,
                               category=category_name,
                               categories=categories,
                               creator=creator)
    else:
        return render_template('item_cat.html',
                               item_catalog=item_catalog,
                               category=category_name,
                               categories=categories,
                               creator=creator)



# Method that  Edit Item from List
@app.route('/catalog/<path:category_name>/<path:item_name>/edit', methods=['GET', 'POST'])
@login_required
def editCategoryItem(category_name, item_name):
        editedItems = session.query(Items).filter_by(name=item_name).first()
        categories = session.query(Category).all()
        creator = getUserInfo(editedItems.user_id)
        user = getUserInfo(login_session['user_id'])
        # If logged in user != item owner redirect them
        if creator.id != login_session['user_id']:
            print("You cannot edit this item. This item belongs to %s" % creator.name)
            return redirect(url_for('Itemcatalog'))
        if request.method == 'POST':
            if request.form['name']:
                name = request.form['name']
                editedItems.name = name
            if request.form['desc']:
                editedItems.desc = request.form['desc']
            if request.form['category']:
                editedItems.category_id = request.form['category']
            time = datetime.datetime.now()
            editedItems.date = time
            session.add(editedItems)
            session.commit()
            return redirect(url_for('Itemcatalog'))
        else:

            return render_template(
                'edit_cat_item.html', item_catalog=editedItems,
                categories=categories)

# Method that Delete Item from List
@app.route('/catalog/item/<item_name>/delete', methods=['GET', 'POST'])
@login_required
def deleteItems(item_name):
    if request.method == 'POST':
        itemsIsDeleted = session.query(Items).filter_by(name=item_name).one()
        session.delete(itemsIsDeleted)
        session.commit()
        return redirect(url_for('Itemcatalog'))
    else:
        user = login_session['username']
        return render_template(
            'delete_cat_item.html', item_name=item_name, user=user
        )



@app.route('/login')
def login():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    return output


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        response = redirect(url_for('index'))
        print("You are now logged out.")
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/catalog/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])

@app.route('/catalog/items/JSON')
def itemsJSON():
    items = session.query(Items).all()
    return jsonify(items=[i.serialize for i in items])

@app.route('/catalog/<path:category_name>/items/JSON')
def categoryItemsJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Items).filter_by(category=category).all()
    return jsonify(items=[i.serialize for i in items])

@app.route('/catalog/<path:category_name>/<path:item_name>/JSON')
def ItemJSON(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Items).filter_by(name=item_name,\
                                        category=category).one()
    return jsonify(item=[item.serialize])





if __name__ == '__main__':
    app.secret_key = '9E4ufbGCIVMrhIcbG475HrYS'
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)