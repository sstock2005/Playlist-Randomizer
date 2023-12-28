# Spotify Playlist Manager

## Overview
This Python script interacts with the Spotify API to manage playlists and fetch user information. It uses the Flask framework to run a local server and handle HTTP requests.

## FAQ
- Does it work with albums? No.
- Does it delete or replace older randomized playlists? No.
- How long does it take? Around 2 minutes at max.

## How it Works
1. The script first reads the configuration values from the `config.yml` file, which includes the Spotify access token and playlist ID.
2. It then starts a Flask server on port 8888.
3. When a user navigates to the server's URL in a web browser, the server responds with the `index.html` page.
4. The user can enter a playlist URL and choose whether to use the Liked Songs playlist.
5. When the user clicks the "Log In" button, the server sends a POST request to the Spotify API to add tracks to the specified playlist.
6. The server prints a success message if the tracks are added successfully, or an error message if there's a problem.

## Optimizations
- The script uses the `requests` library's built-in JSON support to send the playlist data to the Spotify API, which simplifies the code and reduces the chance of errors.
- It also uses Flask's built-in support for serving static files, which makes it easy to serve the `index.html` page.

## Problems
- The script doesn't validate the playlist URL entered by the user, so it could crash if the URL is not a valid Spotify playlist URL.
- It also doesn't handle errors that could occur when reading the `config.yml` file, such as the file not existing or not being in the correct format.
- The script does not delete old Randomized Playlists because for some reason the Spotify Web API did not give me updated playlists so I gave up.

## How to Run
To run the script, use the following command:
```
py main.py
```