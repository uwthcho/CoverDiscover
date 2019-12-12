from secrets import CLIENT_ID, CLIENT_SECRET

GRANT_TYPE = 'authorization_code'

import webapp2, urllib2, os, urllib, json, jinja2, logging, sys, time
import base64, Cookie, hashlib, hmac, email
from google.appengine.ext import db
from google.appengine.api import urlfetch

reload(sys)
sys.setdefaultencoding('utf8')

JINJA_ENVIRONMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
                                       extensions=['jinja2.ext.autoescape'],
                                       autoescape=True)

def pretty(obj):
    return json.dumps(obj, sort_keys=True, indent=2) #TAKE THIS OUT LATER

### this is our user database model. We will use it to store the access_token
class User(db.Model):
    uid = db.StringProperty(required=True)
    displayname = db.StringProperty(required=False)
    img = db.StringProperty(required=False)
    access_token = db.StringProperty(required=True)
    refresh_token = db.StringProperty(required=False)
    profile_url = db.StringProperty(required=False)
    api_url = db.StringProperty(required=False)


### helper functions

### We have some cookie functions here. This lets us be careful
### to make sure that a  malicious user can't spoof your user ID in
### their cookie and then use our site to do things on your behalf
def set_cookie(response, name, value, domain=None, path="/", expires=None):
    """Generates and signs a cookie for the give name/value"""
    timestamp = str(int(time.time()))
    value = base64.b64encode(value)
    signature = cookie_signature(value, timestamp)
    cookie = Cookie.BaseCookie()
    cookie[name] = "|".join([value, timestamp, signature])
    cookie[name]["path"] = path
    if domain: cookie[name]["domain"] = domain
    if expires:
        cookie[name]["expires"] = email.utils.formatdate(
            expires, localtime=False, usegmt=True)
    response.headers.add("Set-Cookie", cookie.output()[12:])


def parse_cookie(value):
    """Parses and verifies a cookie value from set_cookie"""
    if not value: return None
    parts = value.split("|")
    if len(parts) != 3: return None
    if cookie_signature(parts[0], parts[1]) != parts[2]:
        logging.warning("Invalid cookie signature %r", value)
        return None
    timestamp = int(parts[1])
    if timestamp < time.time() - 30 * 86400:
        logging.warning("Expired cookie %r", value)
        return None
    try:
        return base64.b64decode(parts[0]).strip()
    except:
        return None


def cookie_signature(*parts):
    """
    Generates a cookie signature.

    We use the Spotify app secret since it is different for every app (so
    people using this example don't accidentally all use the same secret).
    """
    chash = hmac.new(CLIENT_SECRET, digestmod=hashlib.sha1)
    for part in parts: chash.update(part)
    return chash.hexdigest()


### this adds a header with the user's access_token to Spotify requests
def spotifyurlfetch(url, access_token, params=None):
    headers = {'Authorization': 'Bearer ' + access_token}
    response = urlfetch.fetch(url, method=urlfetch.GET, payload=params, headers=headers)
    return response.content


### handlers

### this handler will be our Base Handler -- it checks for the current user.
### creating this class allows our other classes to inherit from it
### so they all "know about" the user
class BaseHandler(webapp2.RequestHandler):
    # @property followed by def current_user makes so that if x is an instance
    # of BaseHandler, x.current_user can be referred to, which has the effect of
    # invoking x.current_user()
    @property
    def current_user(self):
        """Returns the logged in Spotify user, or None if unconnected."""
        if not hasattr(self, "_current_user"):
            self._current_user = None
            # find the user_id in a cookie
            user_id = parse_cookie(self.request.cookies.get("spotify_user"))
            if user_id:
                self._current_user = User.get_by_key_name(user_id)
        return self._current_user

import YouTube_Key

### this will handle our home page
class HomeHandler(BaseHandler):
    def genpage(self, chosenPlaylist=None):
        coverList= {}
        template = JINJA_ENVIRONMENT.get_template('coverDiscover.html')

        # check if they are logged in
        user = self.current_user
        tvals = {'current_user': user}

        if user != None:
            ## if so, get their playlists
            url = "https://api.spotify.com/v1/users/%s/playlists" % user.uid

            response = json.loads(spotifyurlfetch(url, user.access_token))
            tvals["playlists"] = response["items"]
            #logging.info(pretty(response)) # prints out users playlists JSON

            if chosenPlaylist != None:
                chosenPlaylistID = chosenPlaylist
                #logging.info(chosenPlaylistID)

                ## Once playlist is identified, get songs on the playlist
                url = "https://api.spotify.com/v1/playlists/%s/tracks" % chosenPlaylistID  # make a call for tracks
                response = json.loads(spotifyurlfetch(url, user.access_token))
                tvals["tracks"] = response["items"]  # do we need a new dictionary?
                #logging.info(pretty(tvals["tracks"]))

                tvals['embedded'] = {}
                for track in tvals["tracks"][:10]:
                    song = track['track']["name"]
                    artist = track['track']["artists"][0]["name"]
                    searchQuery = song + " " + artist + " " + 'Cover'

                    baseurl = "https://www.googleapis.com/youtube/v3/search?"
                    api_key = YouTube_Key.key
                    params={"method": "list",
                            "q": searchQuery,
                            "part": "snippet",
                            "order": "relevance",
                            "maxResults": 5,
                            "key": api_key}

                    url = baseurl + urllib.urlencode(params)
                    searchResult = json.load(urllib2.urlopen(url))

                    coverID = searchResult["items"][0]["id"]["videoId"]
                    for video in searchResult['items']:
                        videoTitle = video['snippet']['title']
                        if 'cover' in videoTitle.lower():
                            coverID = video["id"]["videoId"]
                            break

                    songLabel = song + " - " + artist

                    tvals["embedded"][songLabel] = "https://www.youtube.com/embed/" + coverID
                    #logging.info(tvals['embedded'])

        self.response.write(template.render(tvals))

    def get(self):
        self.genpage()

    def post(self):
        chosenPlaylist = self.request.get('chosenPlaylist')
        if chosenPlaylist is not None:
            self.genpage(chosenPlaylist)

class LoginHandler(BaseHandler):
    def get(self):
        # after  login; redirected here
        # did we get a successful login back?
        args = {}
        args['client_id'] = CLIENT_ID

        verification_code = self.request.get("code")
        if verification_code:
            # if so, we will use code to get the access_token from Spotify
            # This corresponds to STEP 4 in https://developer.spotify.com/web-api/authorization-guide/

            args["client_secret"] = CLIENT_SECRET
            args["grant_type"] = GRANT_TYPE
            args["code"] = verification_code  # the code we got back from Spotify
            args['redirect_uri'] = self.request.path_url  # the current page

            # We need to make a post request, according to the documentation

            headers = {'content-type': 'application/x-www-form-urlencoded'}
            url = "https://accounts.spotify.com/api/token"
            response = urlfetch.fetch(url, method=urlfetch.POST, payload=urllib.urlencode(args))
            response_dict = json.loads(response.content)
            logging.info(response_dict["access_token"])
            access_token = response_dict["access_token"]
            refresh_token = response_dict["refresh_token"]

            # Download the user profile. Save profile and access_token
            # in Datastore; we'll need the access_token later

            ## the user profile is at https://api.spotify.com/v1/me
            profile = json.loads(spotifyurlfetch('https://api.spotify.com/v1/me', access_token))
            logging.info(profile)

            user = User(key_name=str(profile["id"]), uid=str(profile["id"]),
                        displayname=str(profile["display_name"]), access_token=access_token,
                        profile_url=profile["external_urls"]["spotify"], api_url=profile["href"],
                        refresh_token=refresh_token)
            if profile.get('images') is not None:
                user.img = profile["images"][0]["url"]
            user.put()

            ## set a cookie so we can find the user later
            set_cookie(self.response, "spotify_user", str(user.uid), expires=time.time() + 30 * 86400)

            ## okay, all done, send them back to the App's home page
            self.redirect("/")
        else:
            # not logged in yet-- send the user to Spotify to do that
            # This corresponds to STEP 1 in https://developer.spotify.com/web-api/authorization-guide/

            args['redirect_uri'] = self.request.path_url
            args['response_type'] = "code"
            # ask for the necessary permissions - see details at https://developer.spotify.com/web-api/using-scopes/
            args['scope'] = "user-library-modify playlist-modify-private playlist-modify-public playlist-read-collaborative"

            url = "https://accounts.spotify.com/authorize?" + urllib.urlencode(args)
            logging.info(url)
            self.redirect(url)


## this handler logs the user out by making the cookie expire
class LogoutHandler(BaseHandler):
    def get(self):
        set_cookie(self.response, "spotify_user", "", expires=time.time() - 86400)
        self.redirect("/")


application = webapp2.WSGIApplication([
    ("/", HomeHandler),
    ("/auth/login", LoginHandler),
    ("/auth/logout", LogoutHandler)
], debug=True)