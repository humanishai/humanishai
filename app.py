#from openai.api_resources.completion import Completion
from flask import Flask, render_template, request
from joblib import dump, load
import sklearn
import psycopg2
import openai
import os

""" This is a flask app that takes picks and displays the contents of the database """

print(os.environ)

app = Flask(__name__)

'''
Pick takes a json object that has key value pairs that are robot_name and robot_item
Both robot_name and robot_item values are strings
Example: https://www.simtooreal.com/pick?item_name=candy bar&robot_name=walle
Output: walle has successfully picked candy bar
'''
@app.route('/pick', methods=['GET', 'POST'])
def pick():
    if request.method == 'POST':
        robot_name = request.args.get('robot_name')
        item_name = request.args.get('item_name')
        return find_ids_and_insert_picks(robot_name, item_name)
    else:
        return "Submit a pick by sending a POST with JSON key value pairs for robot_name and robot_item"

'''
find_ids_and_insert_picks() takes a robot_name and robot_item
both robot_name and robot_item values are strings, if robot and item name do not exist then conveniently
they will be created
Example: find_ids_and_insert_picks('walle', 'candy bar')
Output: walle has successfully picked candy bar
'''
def find_ids_and_insert_picks(robot_name, item_name):
    result = ''

    """ These are the postgres environment variables to avoid storing sensitie info in the github repo """
    POSTGRESQL_HOST = os.environ.get('POSTGRESQL_HOST')
    POSTGRESQL_USER_NAME = os.environ.get('POSTGRESQL_USER_NAME')
    POSTGRESQL_PASSWORD = os.environ.get('POSTGRESQL_PASSWORD')

    """ We use psycopg2 to create a database connection either locally or in AWS """
    conn = psycopg2.connect(host=POSTGRESQL_HOST, port = 5432, database="simtooreal", user=POSTGRESQL_USER_NAME, password=POSTGRESQL_PASSWORD)
    conn.autocommit=True

    """ Create a cursor object """
    cur = conn.cursor()

    """ A query that takes gives the robot_id of robots given their robot_name """
    cur.execute("SELECT * FROM public.robots WHERE robot_name=%(robot_name)s", {'robot_name': robot_name } )
    row = cur.fetchone()

    """ If there is no robot with that name create it in the database and then look up the ID of that new robot """
    if row == None:
        cur.execute("INSERT INTO public.robots values(default,%(robot_name)s);", {'robot_name': robot_name } )
        result += "There were no robots with the name " + robot_name + " so we created it\n"
        cur.execute("SELECT * FROM public.robots WHERE robot_name=%(robot_name)s", {'robot_name': robot_name } )
        row = cur.fetchone()
        

    robot_id = str(f"{row[0]}")

    """ Look up the item ID from the item name """
    cur.execute("SELECT * FROM public.items WHERE item_name=%(item_name)s", {'item_name': item_name } )
    row = cur.fetchone()

    """ If there is no item with that name create it in the database and then look up the ID of that new item """
    if row == None:
        cur.execute("INSERT INTO public.items values(default,%(item_name)s);", {'item_name': item_name } )
        result += "There were no items with the name " + item_name + " so we created it\n"
        cur.execute("SELECT * FROM public.items WHERE item_name=%(item_name)s", {'item_name': item_name } )
        row = cur.fetchone()

    item_id = str(f"{row[0]}")

    """ Now we are ready to store a pick timestamp and IDs """
    cur.execute(f"INSERT INTO public.picks values(default, current_timestamp, {item_id}, {robot_id});")

    '''
    Close the cursor and connection too so the server can allocate
    bandwidth to other requests
    '''
    cur.close()
    conn.close()

    if result == '':
        return f"{robot_name} has successfully picked {item_name}"
    else:
        return result + "<br>" + f"{robot_name} has successfully picked {item_name}"

'''
gpt() takes no arguments but uses form data to ask GPT-3 to translate text to SQL queries
'''
@app.route('/gpt',methods = ['POST', 'GET'])
def gpt():
    if request.method == 'POST':
        human = str(request.form['Human'])
        text = "<h4>You asked GPT-3: " + human + "</h4>"

        openai.api_key = os.environ["OPENAI_API_KEY"]

        # start_sequence = "\nGPT:"
        # restart_sequence = "\nUser: "

        """ Now we have what we need to ask GPT-3 to make SQL queries for us """
        gpt_result = openai.Completion.create(
            engine="davinci-instruct-beta",
            prompt="Instruction: Given an input question, respond with syntactically correct PostgreSQL. Be creative but the SQL must be correct. Only use tables called \"robots\", \"items\", and \"picks\". The \"robots\" table has columns: robot_id (integer), and robot_name (character varying). The \"items\" table has columns: item_id (integer), and item_name (character varying). The \"picks\" table has columns: pick_id (integer), pick_timestamp (timestamp), robot_id (foreign key integer), and item_id (foreign key integer).\nUser: How many robots are there?\nGPT: SELECT COUNT(*) FROM robots\nUser: What is the most recently picked item?\nGPT: SELECT max(pick_timestamp) FROM picks\nUser: What is the robot with the latest pick?\nGPT: SELECT * FROM picks WHERE pick_timestamp = max(pick_timestamp)\nUser: What robots picked the item_name doll?\nGPT: SELECT r.robot_name,p.pick_timestamp FROM public.picks p JOIN public.robots r ON p.robot_id=r.robot_id JOIN public.items i ON p.item_id=i.item_id WHERE i.item_name='doll';\nUser: What items were picked by the robot optimus?\nGPT: SELECT i.item_name,p.pick_timestamp FROM public.picks p JOIN public.robots r ON p.robot_id=r.robot_id JOIN public.items i ON p.item_id=i.item_id WHERE r.robot_name='optimus';\nUser: What robots picked the item sandwich?\nGPT: SELECT r.robot_name,p.pick_timestamp FROM public.picks p JOIN public.robots r ON p.robot_id=r.robot_id JOIN public.items i ON p.item_id=i.item_id WHERE i.item_name='sandwich';\nUser: " + human + "\n",
            temperature=0.3,
            max_tokens=303,
            top_p=1,
            frequency_penalty=0.2,
            presence_penalty=0,
            stop=["\n"]
        )

        text += "<h4>GPT-3 Says: " + gpt_result["choices"][0]["text"].replace("GPT: ","") + "</h4>"

        """ These are the postgres environment variables to avoid storing sensitive info in the github repo """
        POSTGRESQL_HOST = os.environ.get('POSTGRESQL_HOST')
        POSTGRESQL_USER_NAME = os.environ.get('POSTGRESQL_USER_NAME')
        POSTGRESQL_PASSWORD = os.environ.get('POSTGRESQL_PASSWORD')

        """ We use psycopg2 to create a database connection either locally or in AWS """
        conn = psycopg2.connect(host=POSTGRESQL_HOST, port = 5432, database="simtooreal", user=POSTGRESQL_USER_NAME, password=POSTGRESQL_PASSWORD)
        conn.autocommit=True

        """ Create a cursor object """
        cur = conn.cursor()

        """ A query that looks up all robots """
        cur.execute("SELECT * FROM public.robots;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Robots</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        """ A query that looks up all items """
        cur.execute("SELECT * FROM public.items;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Items</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        """ A query that looks up all picks """
        cur.execute("SELECT * FROM public.picks;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Picks</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        """ A query that looks up all questions """
        cur.execute("SELECT * FROM public.questions;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Questions</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        """ A query that looks up all categories """
        cur.execute("SELECT * FROM public.categories;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Categories</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        return text

'''
question() takes no arguments but uses form data to ask sklearn to translate a question to a category
'''
@app.route('/question',methods = ['POST', 'GET'])
def question():
    if request.method == 'POST':
        human = str(request.form['Human'])
        text = "<h4>You asked sklearn: " + human + "</h4>"

        clf = load('clf.joblib')

        text += "<h4>sklearn Says: " + clf.predict([human])[0] + "</h4>"

        """ These are the postgres environment variables to avoid storing sensitive info in the github repo """
        POSTGRESQL_HOST = os.environ.get('POSTGRESQL_HOST')
        POSTGRESQL_USER_NAME = os.environ.get('POSTGRESQL_USER_NAME')
        POSTGRESQL_PASSWORD = os.environ.get('POSTGRESQL_PASSWORD')

        """ We use psycopg2 to create a database connection either locally or in AWS """
        conn = psycopg2.connect(host=POSTGRESQL_HOST, port = 5432, database="simtooreal", user=POSTGRESQL_USER_NAME, password=POSTGRESQL_PASSWORD)
        conn.autocommit=True

        """ Create a cursor object """
        cur = conn.cursor()

        cur.execute("SELECT * FROM public.categories;")
        row = cur.fetchall()
        if row != None:
            text += "<h4>If you could choose a category what would you choose?</h4>"
            cat_dict = {}
            for category in row:
                cat_dict[category] = human

            text += render_template('feedback.html', categories = cat_dict)

        """ A query that looks up all robots """
        cur.execute("SELECT * FROM public.robots;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Robots</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        """ A query that looks up all items """
        cur.execute("SELECT * FROM public.items;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Items</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        """ A query that looks up all picks """
        cur.execute("SELECT * FROM public.picks;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Picks</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        """ A query that looks up all questions """
        cur.execute("SELECT * FROM public.questions;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Questions</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        """ A query that looks up all categories """
        cur.execute("SELECT * FROM public.categories;")
        row = cur.fetchall()
        if row != None:
            text += "<br/><br/><h3>Indices and Categories</h3><br/><br/>"
            for r in row:
                text += str(r)[1:-1] + '<br/>'

        return text

'''
feedback() takes no arguments but uses form data to get data from customers
'''
@app.route('/feedback',methods = ['POST', 'GET'])
def feedback():
    text = ''
    if request.method == 'POST':
        category = str(request.form['submit'])
        text += 'submitted ' + category
        
        """ These are the postgres environment variables to avoid storing sensitive info in the github repo """
        POSTGRESQL_HOST = os.environ.get('POSTGRESQL_HOST')
        POSTGRESQL_USER_NAME = os.environ.get('POSTGRESQL_USER_NAME')
        POSTGRESQL_PASSWORD = os.environ.get('POSTGRESQL_PASSWORD')

        """ We use psycopg2 to create a database connection either locally or in AWS """
        conn = psycopg2.connect(host=POSTGRESQL_HOST, port = 5432, database="simtooreal", user=POSTGRESQL_USER_NAME, password=POSTGRESQL_PASSWORD)
        conn.autocommit=True

        """ Create a cursor object """
        cur = conn.cursor()

        """ Insert new feedback """
        cur.execute("INSERT INTO public.questions values(default,%(question_text)s,%(question_topic)s);", {'question_topic': category.split("category: ")[1], 'question_text': category.split("question: ")[1].split("category: ")[0]})
    
    return text

@app.route('/')
def hello_world():
    result = render_template('gpt.html')
    result += render_template('question.html')

    """ These are the postgres environment variables to avoid storing sensitive info in the github repo """
    POSTGRESQL_HOST = os.environ.get('POSTGRESQL_HOST')
    POSTGRESQL_USER_NAME = os.environ.get('POSTGRESQL_USER_NAME')
    POSTGRESQL_PASSWORD = os.environ.get('POSTGRESQL_PASSWORD')

    """ We use psycopg2 to create a database connection either locally or in AWS """
    conn = psycopg2.connect(host=POSTGRESQL_HOST, port = 5432, database="simtooreal", user=POSTGRESQL_USER_NAME, password=POSTGRESQL_PASSWORD)
    conn.autocommit=True

    """ Create a cursor object """
    cur = conn.cursor()

    """ A query that looks up all robots """
    cur.execute("SELECT * FROM public.robots;")
    row = cur.fetchall()
    if row != None:
        result += "<br/><br/><h3>Indices and Robots</h3><br/><br/>"
        for r in row:
            result += str(r)[1:-1] + '<br/>'

    """ A query that looks up all items """
    cur.execute("SELECT * FROM public.items;")
    row = cur.fetchall()
    if row != None:
        result += "<br/><br/><h3>Indices and Items</h3><br/><br/>"
        for r in row:
            result += str(r)[1:-1] + '<br/>'

    """ A query that looks up all picks """
    cur.execute("SELECT * FROM public.picks;")
    row = cur.fetchall()
    if row != None:
        result += "<br/><br/><h3>Indices and Picks</h3><br/><br/>"
        for r in row:
            result += str(r)[1:-1] + '<br/>'

    """ A query that looks up all questions """
    cur.execute("SELECT * FROM public.questions;")
    row = cur.fetchall()
    if row != None:
        result += "<br/><br/><h3>Indices and Questions</h3><br/><br/>"
        for r in row:
            result += str(r)[1:-1] + '<br/>'

    """ A query that looks up all categories """
    cur.execute("SELECT * FROM public.categories;")
    row = cur.fetchall()
    if row != None:
        result += "<br/><br/><h3>Indices and Categories</h3><br/><br/>"
        for r in row:
            result += str(r)[1:-1] + '<br/>'

    return result


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
