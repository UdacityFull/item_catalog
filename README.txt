Item Catalog Web Application
This web app is a four project for the Udacity Full Stack Web DEveloper NanopDegree Course.
Project Overview
You will develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.
In This Repo
This project has one main Python module application.py 
which runs the Flask application. 
A SQL database is created using the db_setup.py module 
The Flask application uses stored HTML templates in the tempaltes folder to build the front-end of the application. 
CSS/JS are stored in the static directory.
Skills Honed
1-Python
2-HTML
3-CSS
4-OAuth third party
5-Flask Framework
Installation
There are some dependancies and a few instructions on how to run the application.
 Seperate instructions are provided to get GConnect working also.
Dependencies:
*vagrant
*udacity VagrantFile
*virtualBox

How to Install:
1-Install Vagrant & VirtualBox
2-Clone the Udacity Vagrantfile
3-Go to Vagrant directory and either clone this repo or download and place zip here
4-Launch the Vagrant VM (vagrant up)
5-Log into Vagrant VM (vagrant ssh)
6-Navigate to cd/vagrant as instructed in terminal
7-Setup application database python /four_pro/db_setup.py
8-Run application using python /four_pro/application.py
9-Access the application locally using http://localhost:8000
Using Google Login:
To get the Google login working there are a few additional steps:
Go to Google Dev Console
Sign up or Login if prompted
Go to Credentials
Select Create Crendentials > OAuth Client ID
Select Web application
Enter name 'item-catalog'
Authorized JavaScript origins = 'http://localhost:8000'
Authorized redirect URIs = ["http://localhost:8000/login","http://localhost:8000/gconnect"]
Select Create
Copy the Client ID and paste it into the data-clientid in login.html
On the Dev Console Select Download JSON
Rename JSON file to client_secrets.json
Place JSON file in four_pro directory that you cloned from here
Run application using python /four_pro/application.py
JSON Endpoints:
The following are open to the public:

Catalog JSON: /catalog/JSON - Displays the whole catalog. Categories and all items.

Categories JSON: /catalog/categories/JSON - Displays all categories

Category Items JSON: /catalog/<path:category_name>/items/JSON - Displays items for a specific category

Category Item JSON: /catalog/<path:category_name>/<path:item_name>/JSON - Displays a specific category item.
