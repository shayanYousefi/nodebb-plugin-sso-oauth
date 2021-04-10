'use strict';

(function (module) {
    /*
     Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
     hook up NodeBB with your existing OAuth endpoint.

     Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
     or "oauth2" section needs to be filled, depending on what you set "type" to.

     Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

     Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
     a format accepted by NodeBB. Instructions are provided there. (Line 146)

     Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
     */

    const User = require.main.require('./src/user');
    const Groups = require.main.require('./src/groups');
    const db = require.main.require('./src/database');
    const authenticationController = require.main.require('./src/controllers/authentication');

    const async = require('async');

    const passport = module.parent.require('passport');
    const nconf = module.parent.require('nconf');
    const winston = module.parent.require('winston');

    /**
     * REMEMBER
     *   Never save your OAuth Key/Secret or OAuth2 ID/Secret pair in code! It could be published and leaked accidentally.
     *   Save it into your config.json file instead:
     *
     *   {
     *     ...
     *     "oauth": {
     *       "id": "someoauthid",
     *       "secret": "youroauthsecret"
     *     }
     *     ...
     *   }
     *
     *   ... or use environment variables instead:
     *
     *   `OAUTH__ID=someoauthid OAUTH__SECRET=youroauthsecret node app.js`
     */

    const constants = Object.freeze({
        type: 'oauth2',	// Either 'oauth' or 'oauth2'
        name: 'alaa',	// Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
        oauth2: {
            authorizationURL: 'https://github.com/login/oauth/authorize',
            tokenURL: 'https://github.com/login/oauth/access_token',
            clientID: nconf.get('oauth:id'),	// don't change this line
            clientSecret: nconf.get('oauth:secret'),	// don't change this line
        },
        userRoute: 'https://api.github.com/user',	// This is the address to your app's "user profile" API endpoint (expects JSON)
    });

    const OAuth = {};
    let configOk = false;
    let Oauth2Strategy;
    let opts;

    if (!constants.name) {
        winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
    } else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
        winston.error('[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)');
    } else if (!constants.userRoute) {
        winston.error('[sso-oauth] User Route required (library.js:31)');
    } else {
        configOk = true;
    }

    OAuth.getStrategy = function (strategies, callback) {
        if (configOk) {
            Oauth2Strategy = require('passport-oauth2').Strategy;

            // OAuth 2 options
            opts = constants.oauth2;
            opts.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';

            Oauth2Strategy.prototype.userProfile = function (accessToken, done) {

                this._oauth2.useAuthorizationHeaderforGET(true);
                this._oauth2.get(constants.userRoute, accessToken, function (err, body) {

                    if (err) {
                        return done(err);
                    }


                    try {
                        var json = JSON.parse(body);
                        OAuth.parseUserReturn(json, function (err, profile) {
                            if (err) return done(err);
                            profile.provider = constants.name;

                            done(null, profile);
                        });
                    } catch (e) {
                        done(e);
                    }
                });
            };

            opts.passReqToCallback = true;

            passport.use(constants.name,
                new Oauth2Strategy(opts, async (req, accessToken, refreshToken, profile, done) => {
                    console.log('after token profile');
                    console.log(req.body);
                    console.log(accessToken);
                    console.log(refreshToken);
                    console.log(profile);


                    const user = await OAuth.login({
                        oAuthid: profile.id,
                        handle: profile.displayName,
                        email: profile.email,
                        isAdmin: profile.isAdmin,
                    });

                    //requiring email and display name on register
                    req.session.registration = req.session.registration || {};
                    req.session.registration.alaaId = profile.id;
                    req.session.registration.provider = profile.provider;


                    authenticationController.onSuccessfulLogin(req, user.uid);
                    done(null, user);
                }));

            strategies.push({
                name: constants.name,
                url: '/auth/' + constants.name,
                callbackURL: '/auth/' + constants.name + '/callback',
                icon: 'fa-check-square',
                scope: (constants.scope || '').split(','),
            });

            callback(null, strategies);
        } else {
            callback(new Error('OAuth Configuration is invalid'));
        }
    };

    OAuth.parseUserReturn = function (data, callback) {
        // Alter this section to include whatever data is necessary
        // NodeBB *requires* the following: id, displayName, emails.
        // Everything else is optional.

        // Find out what is available by uncommenting this line:
        console.log(data);

        var profile = {};
        profile.id = data.id;
        profile.displayName = data.name;
        profile.email = data.email;


        //return callback(new Error('Congrats! So far so good -- please see server log for details'));


        callback(null, profile);
    };

    OAuth.login = async (payload) => {
        let uid = await OAuth.getUidByOAuthid(payload.oAuthid);
        console.log('sorted');
        console.log(uid);
        if (uid) {
            // Existing User
            return ({
                uid: uid,
            });
        }

        delete payload.email;
        console.log('in login');
        console.log(payload);
        // Check for user via email fallback
        //uid = await User.getUidByEmail(payload.email);
        if (!uid) {
            // New user
            uid = await User.create({
                username: payload.handle,
                email: payload.email,
            });
            console.log('user created');
        }

        console.log('saving user data');
        //Save provider-specific information to the user
        await User.setUserField(uid, constants.name + 'Id', payload.oAuthid);

        await db.setObject(`${constants.name}:id:${payload.oAuthid}`, {
            uid: uid,
            date: Date.now(),
        });
        //await db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

        if (payload.isAdmin) {
            await Groups.join('administrators', uid);
        }

        return {
            uid: uid,
        };
    };

    OAuth.getUidByOAuthid = async (oAuthid) => db.getObjectField(`${constants.name}:id:${oAuthid}`, "uid");

    OAuth.deleteUserData = function (data, callback) {
        async.waterfall([
            async.apply(User.getUserField, data.uid, constants.name + 'Id'),
            function (oAuthIdToDelete, next) {
                db.delete(`${constants.name}:id:${oAuthIdToDelete}`);
            },
        ], function (err) {
            if (err) {
                winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
                return callback(err);
            }

            callback(null, data);
        });
    };

    // If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
    OAuth.whitelistFields = function (params, callback) {
        params.whitelist.push(constants.name + 'Id');
        callback(null, params);
    };

    OAuth.getEmailAndDisplayName = function (data, callback) {

        console.log('in interstitial preparation');
        console.log(data);
        if (data.userData.hasOwnProperty("alaaId")) {
            console.log('in if');
            data.interstitials.push({
                template: "interstitial.tpl",
                data: {},
                callback: OAuth.interstitialCallback,
            });
            console.log(data);
        }
        callback(null, data);
    };

    OAuth.interstitialCallback = function (userdata, data, callback) {

        console.log('in intertitail callback');
        console.log(userdata);
        console.log(data);

        callback();
    };

    module.exports = OAuth;
}(module));
