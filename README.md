### :cat2: miaw.cc 

a lightweight, easy to use python pastebin website.

in production, miaw.cc comes in at only 500kb average, with a fast and efficient backend, as little code as possible, and a simple and intuitive frontend based on the nostalgic themes of the early indie web.

miaw is not made for public/production enviroments, and is simply a small community project. this may change in the future, but as of right now, **no more than ~50 writes can happen simultaneously**.

if you decide to fork it, keep invite codes in the code and keep it to just your friends.

## features

- [x] user registration and login, changing of usernames, passwords, pfp uploads and handling
- [x] sanitized profile css
- [x] dashboard with a search query for pastes
- [x] banned urls
- [x] url claim limit
- [x] create and view pastes
- [x] admin / user management
- [x] search bar for pastes
- [x] ip logging
- [x] password protected pastes
- [x] csrf protection, html/css sanitization
- [x] invite codes

## agreements

by hosting miaw you agree to 
1. make your fork open source
2. not make any profit from your fork
3. not claim the work as your own
4. not allow zionism, homophobia, transphobia or racism of any kind on the platform

## installation

please read the requirements.txt file for dependencies

make sure you are not running other webservers on a 5001 port, or change the port in the app.py file

you will need [python3](https://www.python.org/downloads/) and [pip](https://pip.pypa.io/en/stable/cli/pip_install/) for this project.

you are expected to have a base understanding of python3 and sqlite, however you can pass with just html/css.

i cannot help you personally, please do not reach out to me for questions or support.

```
pip install -r requirements.txt
```
you need to initialize the database by running the following command
```
python3 app.py
```
then you'll need to do this to add a temporary admin user into the database, edit these if you please.
```
python3 init.py
```
once inserted, run the app again to start the server locally on a 5001 port
```
python3 app.py
```

i can't help you with hosting or production enviroments, my best advice will always be self host.

# contributors

- [maxwell](https://git.0x8e.net/coffee)

# legal

miaw, as with all my works, are under the GNU license.
violations of such will be met with legal action.