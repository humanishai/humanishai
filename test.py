import requests
from coolname import generate_slug
""" This is a simple python script that randomly generates names and items for picks """

errors = 0
for i in range(100):
    try:
        response = requests.post('https://www.simtooreal.com/pick?item_name=' + generate_slug() + '&robot_name=' + generate_slug(2))
    except requests.exceptions.ConnectionError:
        """ This happens when there is a connectivity issue, such as being offline """
        raise Exception('Connectivity issue')

    if response.status_code != 200:
        """ This means something went wrong. """
        errors += 1
        raise Exception('POST request response is status {}'.format(response.status_code))

print("number of errors was " + str(errors))
