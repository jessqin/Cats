import requests


class Movie(object):
    def __init__(self, cat_json, detailed=False):
        #if detailed:
        #    self.genres = omdb_json['Genre']
        #    self.director = omdb_json['Director']
        #    self.actors = omdb_json['Actors']
        #    self.plot = omdb_json['Plot']
        #    self.awards = omdb_json['Awards']

        self.id = cat_json['id']
        self.id = cat_json['name']
        self.affection_level = cat_json['affection_level']
        self.child_friendly = cat_json['child_friendly']
        self.type = 'Cat'
        self.id = cat_json['id']
        self.poster_url = omdb_json['Poster']

    def __repr__(self):
        return self.title
        

class CatClient(object):
    def __init__(self, api_key):
        self.sess = requests.Session()
        self.base_url = f'http://api.thecatapi.com/v1/breeds/'


    def search(self, search_string):
        """
        Searches the API for the supplied search_string, and returns
        a list of Media objects if the search was successful, or the error response
        if the search failed.

        Only use this method if the user is using the search bar on the website.
        """
        #search_string = '+'.join(search_string.split())
        #page = 1

        #search_url = f's={search_string}&page={page}'
        search_url = 'search?q={search_string}'

        resp = self.sess.get(self.base_url + search_url)
        
        if resp.status_code != 200:
            raise ValueError('Search request failed; make sure your API key is correct and authorized')

        data = resp.json()
        return (data)

        if data['Response'] == 'False':
            print(f'[ERROR]: Error retrieving results: \'{data["Error"]}\' ')
            return data

        search_results_json = data['Search']
        remaining_results = int(data['totalResults'])

        result = []

        ## We may have more results than are first displayed
        while remaining_results != 0:
            for item_json in search_results_json:
                result.append(Movie(item_json))
                remaining_results -= len(search_results_json)
            page += 1
            search_url = f's={search_string}&page={page}'
            resp = self.sess.get(self.base_url + search_url)
            if resp.status_code != 200 or resp.json()['Response'] == 'False':
                break
            search_results_json = resp.json()['Search']

        return result

    def retrieve_cat_by_id(self, cat_id):
        """ 
        Use to obtain a Movie object representing the movie identified by
        the supplied imdb_id
        """
        cat_url = self.base_url + f'search?/breed_ids={cat_id}'

        resp = self.sess.get(cat_url)

        if resp.status_code != 200:
            raise ValueError('Search request failed; make sure your API key is correct and authorized')

        data = resp.json()

        if data['Response'] == 'False':
            print(f'[ERROR]: Error retrieving results: \'{data["Error"]}\' ')
            return data

        car = Cat(data, detailed=True)

        return cat


## -- Example usage -- ###
if __name__=='__main__':
    import os

    client = CatClient(os.environ.get('CAT_API_KEY'))


    cats = client.search('Bengal')

    for cat in cats:
        print(cat)
    print(len(cats))

    
