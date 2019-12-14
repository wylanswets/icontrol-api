var storage = require('node-persist');
var format = require('util').format;
var debug = require('debug')('iControl');
var request = require('request').defaults({jar: true/*, proxy:"http://localhost:8888", strictSSL:false*/}); // use cookies

module.exports = {
  iControl: iControl
}

/**
 * iControl represents an iControl-based security system (like Xfinity Home, ADT Pulse), and handles logging in
 * and state changes.
 */

function iControl(config) {
  this.system = config.system;
  this.email = config.email;
  this.password = config.password;
  this.pinCode = config.pinCode;

  // interested parties in us being logged in
  this._loginCompleteCallbacks = [];
  this._loggingIn = false;
  this._loggedIn = false;

  storage.initSync();
  // try to load the refresh token if we have one stored from a previous session
  var data = storage.getItem("iControl." + this.email + ".json");
  this._refreshToken = data && data.refresh_token;
  this._accessToken = data && data.access_token;
  this._accessTokenExpires = data && data.access_token_expires;
  this._accessTokenExpiresAt = data && data.access_token_expires_at;
  this._sessionToken = null;
  this._siteID = data && data.site_id;


  this._statusAge = null;
  this._statuses = null;
  this._gettingStatus = false;
  this._statusCompleteCallbacks = [];

}

// inherits(iControl, EventEmitter);

iControl.Systems = {
  XFINITY_HOME: {
    oauthLoginURL: "https://oauth.xfinity.com/oauth/",
    clientID: "Xfinity-Home-iOS-App",
    clientSecret: "77b366f9a135c7ab391044234a26b1d6b1e08f66",
    clientRedirect: "xfinityhome://auth",
    restAPI: "https://xhomeapi-lb-prod.codebig2.net/",
    eventURL: "https://xhomeapi-lb-prod.apps.cloud.comcast.net/client/icontrol/delta?spsId="
  }
}

iControl.ArmState = {
  DISARMED: "disarmed",
  ARMED_AWAY: "away",
  ARMED_NIGHT: "night",
  ARMED_STAY: "stay"
}


iControl.prototype._generateSpsId = function(callback) {

  if (this._loggingIn || !this._accessToken) {
    // try again when we're logged in

    this.login(function(err) {
      if (err) return callback(err);
      this._generateSpsId(callback); // login successful - try again!
    }.bind(this));

    return;
  }

  var spsID = this._siteID + "-" + Date.now() + "-" + (1e8 * Math.random()).toString(16).replace(".", "");
  callback(spsID);
}


iControl.prototype.subscribeEvents = function(callback) {

  var self = this;
  
  //URL for xfinity home is https://xhomeapi-lb-prod.apps.cloud.comcast.net/client/icontrol/delta?spsId={spsID}
  
  this._generateSpsId(function(spsID) {
    var url = self.system.eventURL + spsID;

    var opts = {
      url: url,
      // headers: {
      //   'Accept': 'application/json',
      //   'X-Client-Features': 'no-cookie,auth4all' //this is required for some reason if not there, api will return "UNAUTHORIZED / RESTRICTED user" or something
      // },
      // auth: {
      //   bearer: self._accessToken
      // }
    };

    self._makeAuthenticatedRequest(opts, function(data, error) {
      if(error !== null) {
        callback(error, null);
      } else {
        callback(null, data);
      }
    });

  })

}

/**
 * Login Process
 */

 iControl.prototype.login = function(callback) {
  //  console.log("Testing");
   // queue this callback for when we're finished logging in
   if (callback) {
    this._loginCompleteCallbacks.push(callback);
    // console.log("cached callback");
   }
     


   // begin logging in if we're not already doing so
   if (!this._loggingIn) {
     this._loggingIn = true;
     this._beginLogin();
   }
 }

 // called way down below when we're done with the oauth dance
 iControl.prototype._loginComplete = function(err) {
  //  console.log("Logged in.");
   this._loggingIn = false;
   this._loggedIn = true;
   this._loginCompleteCallbacks.forEach(function(callback) { callback(err); });
   this._loginCompleteCallbacks = [];
  //  console.log("Logged in");
 }

iControl.prototype._beginLogin = function() { 
  //use existing accessToken
  var date = new Date();
  if (this._accessTokenExpiresAt !== null && (date.getTime() < this._accessTokenExpiresAt)) {
    console.log("Using existing access token.");
    this._loginComplete();
    return;
  }
  if (this._refreshToken) { // try to use the refresh token if we have one; skip the really slow login process
    console.log("Getting new access token with refresh token.");
    this._getAccessToken(null);
    return;
  }

  var url = this.system.oauthLoginURL + "authorize";

  var qs = {
    client_id: this.system.clientID,
    response_type: "code",
    redirect_uri: this.system.clientRedirect
  };

  request(url, {qs:qs, followRedirect: false}, function (redirectErr, redirectResponse, redirectBody) {

    if (!redirectErr && redirectResponse.statusCode == 302 && redirectResponse.headers['location'] != null) {

      var redirectURL = redirectResponse.headers['location'];

      debug('Redirected to %s', redirectURL);

      redirectURL = redirectURL.replace('&client_id=Xfinity-Home-iOS-App', '');
      
      request(redirectURL, function (err, response, body) {

        if (!err && response.statusCode == 200 && response.headers['content-type'].indexOf("text/html") == 0) {

          // the response is an HTML login page. Suck out the hidden input fields so we can simulate a form submit
          var actionRegex = /<form.*action="([^"]+)"/g;
          var formRegex = /<input type="hidden" name="([^"]+)" value="([^"]+)">/g;

          var action = actionRegex.exec(body)[1]; // i.e. https://login.comcast.net/login
          debug("Submitting form with action = %s", action);

          var form = {
            user: this.email,
            passwd: this.password,
            rm: 1 // "remember me?"
          };

          for (var match = formRegex.exec(body); match != null; match = formRegex.exec(body)) {
            var name = match[1];
            var value = match[2];
            debug("Hidden input %s = %s", name, value);
            form[name] = value;
          }

          this._submitLoginPage(action, form);
        }
        else {
          err = err || new Error("Invalid response code " + response.statusCode)
          this._notifyError(err, response, body);
          this._loginComplete(err);
        }
      }.bind(this));

    }
    else {
      err = err || new Error("Invalid response code " + redirectResponse.statusCode)
      this._notifyError(redirectErr, redirectResponse, redirectBody);
      this._loginComplete(redirectErr);
    }

  }.bind(this));
}

iControl.prototype._submitLoginPage = function(url, form) {

  request.post(url, {form:form}, function(err, response, body) {
    // we expect a redirect response
    if (!err && response.statusCode == 302) {

      // either iControl is wrong in HTML-encoding "&" characters in the location header, or the request
      // library isn't decoding it correctly. Either way, @#$ IT, WE'LL DO IT LIVE
      var location = response.headers.location.replace(/&amp;/g, "&");

      this._getAuthorizationCode(location);
    }
    else {
      err = err || new Error("Bad status code " + response.statusCode);
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }
  }.bind(this));
}

iControl.prototype._getAuthorizationCode = function(url) {

  var followRedirect = function(response) {
    var isAppURL = (response.headers.location.indexOf(this.system.clientRedirect) == 0);
    var shouldRedirect = !isAppURL; // don't auto-redirect to non-http URLs
    return shouldRedirect;
  }.bind(this);

  request(url, {followRedirect: followRedirect}, function(err, response, body) {
    // we expect a redirect-to-app response
    if (!err && response.statusCode == 302) {

      var location = response.headers.location; // e.g. xfinityhome://auth?code=xyz
      var code = (/auth\?code=(.*)/).exec(location)[1];

      this._getAccessToken(code);
    }
    else {
      err = err || new Error("Invalid status code " + response.statusCode);
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }
  }.bind(this));
}

iControl.prototype._getAccessToken = function(authorizationCode) {
  var url = this.system.oauthLoginURL + "token";
  var form = {
    client_id: this.system.clientID,
    client_secret: this.system.clientSecret,
    redirect_uri: this.system.clientRedirect,
  };

  // use a authorizationCode if given, otherwise use our refresh token
  if (authorizationCode) {
    console.log("Logging in with authorization code from web form...");
    form.code = authorizationCode;
    form.grant_type = "authorization_code";
  }
  else {
    console.log("Logging in with previously stored refresh token...");
    form.refresh_token = this._refreshToken;
    form.grant_type = "refresh_token";
  }
  request.post(url, {form:form}, function(err, response, body) {
    if (!err && response.statusCode == 200) {

      /* response is JSON like:
      {
      	"access_token": "CgNPQ...",
      	"token_type": "Bearer",
      	"refresh_token": "TJrPm...",
      	"expires_in": 3599,
      	"scope": "https://molecule.g.comcast.net/client https://secure.api.comcast.net/homesecurity/cvr#read https://login.comcast.net/api/login openid",
      	"id_token": "eyJhbGciO..."
      }
      */
      
      var json = JSON.parse(body);
      var curDate = new Date();
      var expiresDate = new Date(curDate.getTime() + (1000 * json.expires_in));
      this._refreshToken = json.refresh_token;
      this._accessToken = json.access_token;
      this._accessTokenExpires = json.expires_in;
      this._accessTokenExpiresAt = expiresDate.getTime();

      var self = this;

      var req = {
        path: "client"
      }
      
      this._makeAuthenticatedRequest(req, function(data) {
        //Force site ID to be set
        self._siteID = data.site.id;
          storage.setItem("iControl." + self.email + ".json", {
            site_id: self._siteID,
            access_token: self._accessToken,
            access_token_expires: self._accessTokenExpires,
            access_token_expires_at: self._accessTokenExpiresAt,
            refresh_token: self._refreshToken,
          });
          self._loggedIn = true;
          self._loginComplete();  
      }, true);

    }
    else if (!authorizationCode && !err && (response.statusCode == 400 || response.statusCode == 401)) {

      // we tried to log in with a refresh token and it was rejected or expired.
      // Nuke it and try logging in again without one.
      // console.log("Refresh token was rejected. Trying login from web form...");
      this._refreshToken = null;
      this._beginLogin();
    }
    else {
      err = err || new Error("Invalid status code " + response.statusCode);
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }

  }.bind(this));
}

iControl.prototype._getCurrentStatus = function(callback) {


  if(this._gettingStatus) {
    //Wait to fire this function again until previous request is done
    //We should also get a cached response on this making this fast.
    this._statusCompleteCallbacks.push(callback);
    return;
  }

  
  //Because all statuses come back in a single call - we have to do a short lived cache
  //to keep the number of requests down.
  if(this._statuses !== null) {
    var now = new Date();
    var diff = now.getTime() - this._statusAge;
    //Cache of 3 seconds is used.
    if(diff < 3000) {
      callback(this._statuses);
      return;
    }
  }

  this._gettingStatus = true;

  var opts = {
    path: "client",
    method: 'GET'
  };

  var self = this;
  this._makeAuthenticatedRequest(opts, function(data, error) {
    var json = data;
    self._statuses = json;
    var date = new Date();
    self._statusAge = date.getTime();
    self._gettingStatus = false;
    callback(self._statuses);
    var statuses = self._statuses;
    self._statusCompleteCallbacks.forEach(function(callback) { callback(statuses); });
    self._statusCompleteCallbacks = [];

  });

}

iControl.prototype._getAccessories = function(callback) {


  this._getCurrentStatus(function(status) {
    var json = status;

    //API seems to have changed to only return "site" as a first-class element
    this._siteID = json.site.id;

    //console.log(json.devices);
    var foundDevices = [];
    var devices = json.devices;
    for(var i in devices) {
      var device = devices[i];
      switch(device.deviceType) {
        case "lightSwitch":
            //foundDevices.push(device);
            // console.log("switch: " + device.name);
            break;
        case "lightDimmer":
            //foundDevices.push(device);
            // console.log("dimmer: " + device.name);
            break;
        case "panel":
            foundDevices.push(device);
            break;
        default:
            //console.log('not supported:' + device.deviceType);
            break;
      }
    }

    callback(foundDevices);
  })


}

/**
 * Helper method for making a request that requires login (will login first if necessary).
 */

iControl.prototype._makeAuthenticatedRequest = function(req, callback, override) {

  // if we're currenly logging in, then call login() to defer this method - also call login
  // if we don't even have an access token (meaning we've never logged in this session)
  // console.log("request 1");
  //Override is used during initial login function to bypass the callback cache and run right now.
  if(!override) {
    if (this._loggingIn || !this._accessToken) {
      // try again when we're logged in
      // console.log("Deferring request '%s' until login complete.", req.path);
  
      this.login(function(err) {
        if (err) return callback(err);
        this._makeAuthenticatedRequest(req, callback); // login successful - try again!
      }.bind(this));
  
      return;
    }
  }
  var self = this;
  // check if token is expired and auto-start login process before bothering to try below request
  // we will likely have a refresh token on hand so this should be fast.
  var date = new Date();
  if(date.getTime() >= this._accessTokenExpiresAt) {
    this._accessToken = null;
    this._accessTokenExpiresAt = null;
    this._accessTokenExpires = null;
    this.login(function(err) {
      if (err) return callback(err);
      self._makeAuthenticatedRequest(req, callback); // login successful - try again!
    }.bind(this));
    return;
  }
  //A few requests will define the full URL when it is different from the restAPI URL base.
  if(req.path !== undefined) {
    //Translate from just the path to the full URL
    req.url = this.system.restAPI + req.path;
  }

  // req.url = this.system.restAPI + req.path;
  req.auth = {bearer:this._accessToken};
  req.headers = req.headers || {};
  req.headers['X-Client-Features'] = 'no-cookie,auth4all';
  
  request(req, function(err, response, body) {
    if (!err && response.statusCode == 200 && response.headers['content-type'].indexOf('json') != -1) {
      var json = JSON.parse(body);
      callback(json, null);
    }
    else if (!err && (response.statusCode == 400 || response.statusCode == 401)) {
      // our access token was rejected or expired - time to log in again
      this._accessToken = null;
      this._accessTokenExpires = null;

    //   // try again when we're logged in
      this.login(function(err) {
        if (err) return callback(null, err);
        self._makeAuthenticatedRequest(req, callback); // login successful - try again!
      }.bind(this));
    }
    else {
      err = err || new Error("Invalid status code " + response.statusCode);
      this._notifyError(err, response, body);
      callback(null, err);
    }

  }.bind(this));
}

iControl.prototype._notifyError = function(err, response, body) {
  var message = format("There was an error while communicating with iControl. Status code was %s and error was: %s\nStack:%s\nResponse:\n%s", response && response.statusCode, err, new Error().stack, body);
  console.log(message);
  // this.emit('error', new Error(message));
}
