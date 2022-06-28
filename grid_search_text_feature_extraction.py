
"""
==========================================================
Sample pipeline for text feature extraction and evaluation
==========================================================

The dataset used in this example is the text/topic dataset which will be
automatically downloaded and then cached and reused for the document
classification example.

You can adjust the number of categories by giving their names to the dataset
loader or setting them to None to get all of them.

Here is a sample output of a run on a mac:

      Unnamed: 0                                      question_text      question_topic
0              0  Hi! If I sign up for your email list, can I se...    Sales/Promotions
1              1  I'm going to be out of the country for about a...            Shipping
2              2  I was wondering if you'd be able to overnight ...            Shipping
3              3  The Swingline electronic stapler (472555) look...            Shipping
4              4  I think this cosmetic bag would work great for...            Shipping
...          ...                                                ...                 ...
4995        4995  Is there a Lululemon in Des Moines, IA? Are yo...         Omnichannel
4996        4996  I want to buy either the Ellison recliner 5363...  Product Comparison
4997        4997  I'm considering buying either the Liver care d...  Product Comparison
4998        4998  I'm considering buying either the PecraClear d...  Product Comparison
4999        4999  I'm considering buying either the women's deto...  Product Comparison

[5000 rows x 3 columns]
['Sales/Promotions', 'Shipping', 'Product Availability', 'Product Specifications', 'Omnichannel', 'Product Comparison', 'Returns & Refunds']
Loading dataset for categories:
None
Performing grid search...
pipeline: ['vect', 'tfidf', 'clf']
parameters:
{'clf__alpha': (1e-05, 1e-06),
 'clf__max_iter': (20,),
 'clf__penalty': ('l2', 'elasticnet'),
 'vect__max_df': (0.5, 0.75, 1.0),
 'vect__ngram_range': ((1, 1), (1, 2))}
Fitting 5 folds for each of 24 candidates, totalling 120 fits
sample_text: Hi! If I sign up for your email list, can I select to get emails exclusively for sale products? I'm really only interested in shopping clearance deals.
prediction: Sales/Promotions
done in 8.379s

Best score: 0.968
Best parameters set:
	clf__alpha: 1e-05
	clf__max_iter: 20
	clf__penalty: 'elasticnet'
	vect__max_df: 0.5
	vect__ngram_range: (1, 2)
"""



# Author: Olivier Grisel <olivier.grisel@ensta.org>
#         Peter Prettenhofer <peter.prettenhofer@gmail.com>
#         Mathieu Blondel <mathieu@mblondel.org>
# License: BSD 3 clause
from pprint import pprint
from time import time
from time import sleep
import logging
import psycopg2
import itertools

#from sklearn.datasets import fetch_20newsgroups
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.pipeline import Pipeline
from joblib import dump, load
import pandas
import os

print(__doc__)

# Display progress logs on stdout
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')


# #############################################################################
# Load some categories from the training set
df = pandas.read_csv('topics.csv')
print(df)
cats = df['question_topic'].values.tolist()
print(list(dict.fromkeys(cats)))
# categories = [
#     'alt.atheism',
#     'talk.religion.misc',
# ]
# Uncomment the following to do the analysis on all the categories
categories = None

print("Loading dataset for categories:")
print(categories)

# data = fetch_20newsgroups(subset='train', categories=categories)
# print("%d documents" % len(data.filenames))
# print("%d categories" % len(data.target_names))
label_train = df['question_topic']
text_train = df['question_text']

# #############################################################################
# Define a pipeline combining a text feature extractor with a simple
# classifier
pipeline = Pipeline([
    ('vect', CountVectorizer()),
    ('tfidf', TfidfTransformer()),
    ('clf', SGDClassifier()),
])

# uncommenting more parameters will give better exploring power but will
# increase processing time in a combinatorial way
parameters = {
    'vect__max_df': (0.5, 0.75, 1.0),
    # 'vect__max_features': (None, 5000, 10000, 50000),
    'vect__ngram_range': ((1, 1), (1, 2)),  # unigrams or bigrams
    # 'tfidf__use_idf': (True, False),
    # 'tfidf__norm': ('l1', 'l2'),
    'clf__max_iter': (20,),
    'clf__alpha': (0.00001, 0.000001),
    'clf__penalty': ('l2', 'elasticnet'),
    # 'clf__max_iter': (10, 50, 80),
}

if __name__ == "__main__":
    while True:
        # multiprocessing requires the fork to happen in a __main__ protected
        # block

        # take newly labeled data out of database from customers
        """ These are the postgres environment variables to avoid storing sensitie info in the github repo """
        POSTGRESQL_HOST = os.environ.get('POSTGRESQL_HOST')
        POSTGRESQL_USER_NAME = os.environ.get('POSTGRESQL_USER_NAME')
        POSTGRESQL_PASSWORD = os.environ.get('POSTGRESQL_PASSWORD')
        POSTGRESQL_HOST = os.environ.get('POSTGRESQL_HOST')

        """ We use psycopg2 to create a database connection either locally or in AWS """
        conn = psycopg2.connect(host=POSTGRESQL_HOST, port = 5432, database="simtooreal", user=POSTGRESQL_USER_NAME, password=POSTGRESQL_PASSWORD)
        conn.autocommit=True

        """ Create a cursor object """
        cur = conn.cursor()

        """ A query that takes gives the question_text data """
        cur.execute("SELECT question_text FROM public.questions;")
        rows = cur.fetchall()
        df1 = pandas.DataFrame(rows)
        print("data from the database")
        print(df1)
        print("data from the training file")
        print(text_train)

        """ if there is more data to collect from the database labeled by customers it will be collected and trained on """
        if rows != None:
            text_combined = pandas.concat([text_train,df1], ignore_index=True,keys=['question_text'])

        print("combined data")
        print(text_combined)

        """ A query that gives the question_topics """
        cur.execute("SELECT question_topic FROM public.questions;")
        rows = cur.fetchall()
        df2 = pandas.DataFrame(rows)
        print("labels from the database")
        print(df2)
        print("labels from the training file")
        print(label_train)

        """ if there is more data to collect from the database labeled by customers it will be collected and trained on """
        if rows != None:
            label_combined = pandas.concat([label_train,df2], ignore_index=True,keys=['question_topic'])

        print("combined label")
        print(label_combined)

        # find the best parameters for both the feature extraction and the
        # classifier
        grid_search = GridSearchCV(pipeline, parameters, n_jobs=-1, verbose=1)

        print("Performing grid search...")
        print("pipeline:", [name for name, _ in pipeline.steps])
        print("parameters:")
        pprint(parameters)
        t0 = time()
        clf = grid_search.fit(text_combined, label_combined)
        dump(clf, 'clf.joblib')
        sample_text = "Hi! If I sign up for your email list, can I select to get emails exclusively for sale products? I'm really only interested in shopping clearance deals."
        print("sample_text: " + sample_text)
        print("prediction: " + clf.predict([sample_text])[0])
        print("done in %0.3fs" % (time() - t0))
        print()

        print("Best score: %0.3f" % grid_search.best_score_)
        print("Best parameters set:")
        best_parameters = grid_search.best_estimator_.get_params()
        for param_name in sorted(parameters.keys()):
            print("\t%s: %r" % (param_name, best_parameters[param_name]))
        
        # We only change the pickle file when there is something to be changed
        if os.system("git status | grep modified") == 0:
            os.system("git add .")
            os.system("git commit -m 'updating pickle inference model'")
            os.system("git push origin main")
            os.system("git pull origin main --rebase")

        secs = 86400
        print("waiting " + str(secs) + " seconds before training again")
        sleep(secs)
