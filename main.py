
# Added required imports
from flask import Flask, flash, jsonify, make_response, redirect, request, render_template, url_for
import random
import string
import urllib.parse
import requests
import base64
import re
import yaml

# Initialize App
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Add spotify API variables
with open('config.yml', 'r') as file:
    config = yaml.safe_load(file)

client_id = config['DEFAULT']['CLIENT_ID']
client_secret = config['DEFAULT']['CLIENT_SECRET']
redirect_uri = config['DEFAULT']['REDIRECT_URI']

# Function to generate random 16 character string for state variable in spotify api login
def generate_random_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

# Function to update cached refresh tokens
def update_cache(message, display_name, refresh_token):
    # Set the response body and status code
    resp = make_response(message, 200)

    # Set cookies. Note that cookies can only store string values.
    resp.set_cookie('display_name', display_name)
    resp.set_cookie('refresh_token', refresh_token)

    return resp

# Index Page
@app.route('/')
def index():
    try:
        login = request.base_url + "callback?rtoken={}".format(request.cookies.get('refresh_token'))
        return render_template('index.html', login_url=login, display_name=request.cookies.get('display_name'))
    except:
        return redirect("/login")

# Spotify API Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    playlist_url = request.form.get('playlist_url', None)
    isLiked = request.form.get('isLiked', False)
    
    if isLiked == "on":
        playlist_id = "liked"
    else:
        if playlist_url is not None:
            playlist_id = playlist_url.split('/')[-1].split('?')[0]
        else:
            return "invalid playlist url", 400
        
    if re.match(r'^[0-9a-zA-Z]{22}$', playlist_id) == False:
        return "invalid playlist url", 400
    
    # Set the state variable for the Spotify API
    # https://developer.spotify.com/documentation/web-api/tutorials/code-flow
    state = generate_random_string(16)

    # Set the scope of what we are doing with the end user account, they have to agree to Spotify's tos
    scope = 'user-library-read playlist-modify-public playlist-modify-private user-read-private user-read-email playlist-read-private'

    # Create our request
    spotify_authorize_url = 'https://accounts.spotify.com/authorize?' + urllib.parse.urlencode({
        'response_type': 'code',
        'client_id': client_id,
        'scope': scope,
        'redirect_uri': redirect_uri,
        'state': state
    })

    # Redirect end user to their servers
    resp = make_response("<meta http-equiv=\"refresh\" content=\"1; URL={}\" />".format(spotify_authorize_url), 200)

    # Set cookies. Note that cookies can only store string values.
    resp.set_cookie('playlist_id', playlist_id)

    return resp

# Function to generate playlist and get id from it
def generate(access_token, playlist_id, user_id):
    if access_token == None or user_id == None:
        return None
    if playlist_id == None:
        return None
    if playlist_id == "liked":
        # generate liked playlist
        playlist_name = "Liked Songs"
        liked = get_liked(access_token)
        total = len(liked)
        new_playlist = []

        while len(new_playlist) < total:
            song_index = random.randint(0, len(liked) - 1)
            new_playlist.append(liked[song_index])
            liked.pop(song_index)
    else:
        # generate playlist from playlist
        playlist_name = get_playlist(playlist_id, access_token)['name']
        playlist = get_items(playlist_id, access_token)
        total = playlist['total']
        new_playlist = []

        while len(new_playlist) < total:
            song_index = random.randint(0, len(playlist['items']) - 1)
            new_playlist.append(playlist['items'][song_index])
            playlist['items'].pop(song_index)
        
    # Generated Playlist
    generated_playlist = create_playlist(access_token=access_token, user_id=user_id, playlist_name="{} Randomized".format(playlist_name), playlist_description="Created by Sam Stockstrom")['id']

    # add newly ordered songs in batches of 100 to new playlist
    for i in range(0, total, 100):
        batch_tracks = new_playlist[i:i + 100]
        track_uris = [f"spotify:track:{track['track']['id']}" for track in batch_tracks]
        add_tracks_to_playlist(access_token, generated_playlist, track_uris, position=i)

    return generated_playlist

# Callback function to recieve login data from Spotify
@app.route('/callback')
def callback():
    # Initialize access token and refresh token
    access_token = None
    refresh_token = None
    # Get the authorization code from Spotify
    # https://developer.spotify.com/documentation/web-api/tutorials/code-flow
    code = request.args.get('code', None)

    # Get the state of the request
    state = request.args.get('state', None)

    # Get refresh token if saved
    refresh_token_saved = request.args.get('rtoken', None)

    # If refresh token exists
    if refresh_token_saved is not None:

        # Try to generate new access token and refresh token for that access token
        try:
            x = get_refresh_token(refresh_token_saved)
            access_token = x["access_token"]
            refresh_token = x["refresh_token"]

        # oh well, log in normal
        except:
            return redirect('/login')
        
    # if regular log in
    if code != None and state != None:
        auth_options = {
            'url': 'https://accounts.spotify.com/api/token',
            'form': {
                'code': code,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            },
            'headers': {
                'content-type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            },
            'json': True
        }

        response = requests.post(auth_options['url'], data=auth_options['form'], headers=auth_options['headers'])

        # get authorization
        x = response.json()
        access_token = x['access_token']
        refresh_token = x['refresh_token']
        
    # Get User info
    user = get_user_info(access_token)
    user_id = user['id']
    playlist_id = request.cookies.get('playlist_id', None)
    if playlist_id is None:
        return update_cache("No playlist id found", user['display_name'], refresh_token)
    
    new_playlist = generate(access_token, playlist_id, user_id)
    response = "<meta http-equiv=\"refresh\" content=\"1; URL=https://open.spotify.com/playlist/{}\" />".format(new_playlist)
    # return success
    return update_cache(response, user['display_name'], refresh_token)

# Function to get new access token with a refresh token
# https://developer.spotify.com/documentation/web-api/tutorials/refreshing-tokens
def get_refresh_token(refresh_token):

    # API ENDPOINT
    url = 'https://accounts.spotify.com/api/token'
    
    # AUTH HEADERS
    auth_headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    }

    # INFO
    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }

    # RESPONSE
    response = requests.post(url, headers=auth_headers, data=payload)
    response_data = response.json()
    return response_data

# Function to get Liked Songs Playlist on Spotify because we have to do it this dumb way
# https://developer.spotify.com/documentation/web-api/reference/get-users-saved-tracks
def get_liked(access_token):

    # Initialize a list to return items in 
    all_items = []

    # Initialize API Endpoint
    api_url = "https://api.spotify.com/v1/me/tracks"

    # Tell dev what we're sending
    print("Doing {}".format(api_url))

    # Initialize header
    headers = {
        'Authorization': 'Bearer ' + access_token
    }

    # Get response data
    response = requests.get(api_url, headers=headers)
    data = response.json()

    # Get total number of liked songs
    total = int(data['total'])

    # Get all songs in liked songs, have to do in batches of 50
    # https://developer.spotify.com/documentation/web-api/reference/get-users-saved-tracks
    for offset in range(0, total, 50):
        print("Sending {}".format(api_url))
        params = {'limit': 50, 'offset': offset}
        response = requests.get(api_url, params=params, headers=headers)
        batch_data = response.json()
        batch_items = batch_data.get('items', [])
        all_items.extend(batch_items)

    return all_items

# Function to get items from a given playlist
def get_items(playlist_id, access_token, offset=0):
    url = f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks"
    headers = {
        'Authorization': f'Bearer {access_token}',
    }
    params = {
        'limit': 50,
        'offset': offset,
    }

    response = requests.get(url, headers=headers, params=params)

    # Check if the request was successful
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Function to get playlist info
# https://developer.spotify.com/documentation/web-api/reference/get-playlist
def get_playlist(playlist_id, access_token):
    url = f"https://api.spotify.com/v1/playlists/{playlist_id}"
    headers = {
        'Authorization': f'Bearer {access_token}',
    }
    response = requests.get(url, headers=headers)
    return response.json()

# Function to create a new playlist
# https://developer.spotify.com/documentation/web-api/reference/create-playlist
def create_playlist(access_token, user_id, playlist_name, playlist_description):

    # Initalize API Endpoint
    api_url = f'https://api.spotify.com/v1/users/{user_id}/playlists'

    # Tell dev what we're doing
    print("Doing {}".format(api_url))

    # Set headers
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Set data
    data = {
        'name': playlist_name,
        'description': playlist_description,
        'public': 'false'
    }

    # Get response
    response = requests.post(api_url, headers=headers, json=data)

    # Success
    if response.status_code == 201:
        print(f"Playlist '{playlist_name}' created successfully.")
        return response.json()
    # Error
    else:
        print(f"Error creating playlist: {response.status_code}, {response.text}")
        return None

# Function to get user info (id)
# https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile
def get_user_info(access_token):

    # Initialize API Endpoint
    api_url = 'https://api.spotify.com/v1/me'

    # Tell dev what we doin
    print("Doing {}".format(api_url))

    # Set headers
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    # Get response
    response = requests.get(api_url, headers=headers)

    # success
    if response.status_code == 200:
        return response.json()
    # error
    else:
        print(f"Error fetching user info: {response.status_code}, {response.text}")
        return None

# Function to get current user playlists
# https://developer.spotify.com/documentation/web-api/reference/get-a-list-of-current-users-playlists
def get_spotify_playlists(access_token):
    url = 'https://api.spotify.com/v1/me/playlists'
    params = {'limit': 20, 'offset': 0}
    headers = {'Authorization': f'Bearer {access_token}'}

    response = requests.get(url, params=params, headers=headers)

    if response.status_code == 200:
        # Successful request, return the JSON response
        return response.json()
    else:
        # Print an error message if the request was not successful
        print(f"Error: {response.status_code}")
        return None

# Function to add tracks to a playlist [100 tracks max per request :(]
# https://developer.spotify.com/documentation/web-api/reference/add-tracks-to-playlist
def add_tracks_to_playlist(access_token, playlist_id, track_uris, position=0):

    # Initialize API Endpoint
    api_url = f'https://api.spotify.com/v1/playlists/{playlist_id}/tracks'

    # Tell dev what we doin
    print("Doing {}".format(api_url))

    # Headers
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Data
    data = {
        'uris': track_uris,
        'position': position
    }

    # Get response
    response = requests.post(api_url, headers=headers, json=data)

    # Success
    if response.status_code == 201:
        print("Tracks added to the playlist successfully.")
        return response.json()
    # Error
    else:
        print(f"Error adding tracks to the playlist: {response.status_code}, {response.text}")
        return None
    
# Main function
if __name__ == '__main__':

    # Run app on port 8888
    app.run(port=8888)