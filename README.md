# COEN351 Blue
Blue Team attempt at a simple but secure e-commerce website.

Users are able to transfer credits to other users.
Credits are absolutely worthless because users can simply add credits to their account for no cost.

## Local Installation

Python 2.7+ required.
pip and virtualenv highly recommended.
See requirements.txt for required packages.

### Without virtualenv

1. git clone
2. cd COEN351
3. pip install -r requirements.txt
4. export FLASK_APP=main.py
5. flask run

### With virtualenv

I highly recommend using virtualenv, as to not interfere with current Python packages

1. install virtualenv
2. git clone
3. cd COEN351
4. virtualenv .
5. source bin/activate
6. pip install -r requirements
7. export FLASK_APP=main.py
8. flask run

## Heroku

If time allows, we'll host this on Heroku.

## To Be Developed

- Add Credits -
- Credit Transfer -
- Client Side Input Validation / Notifications  
