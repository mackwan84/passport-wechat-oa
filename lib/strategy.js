/**
 * Module dependencies.
 */
var util = require('util'),
    url = require('url'),
    uid = require('uid2'),
    _ = require('lodash'),
    WechatOAuth = require('wechat-oauth'),
    OAuth2Strategy = require('passport-oauth2').Strategy,
    AuthorizationError = require('passport-oauth2').AuthorizationError,
    InternalOAuthError = require('passport-oauth2').InternalOAuthError;

function WechatStrategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://open.weixin.qq.com/connect/oauth2/authorize';
    options.tokenURL = options.tokenURL || 'https://api.weixin.qq.com/sns/oauth2/access_token';
    options.scope = options.scope || 'snsapi_userinfo';
    options.scopeSeparator = options.scopeSeparator || ' ';
    options.passReqToCallback = true;
    options.state = true;
    OAuth2Strategy.call(this, options, verify);

    this.name = 'wechat';
    this._wechatOAuth = new WechatOAuth(options.clientID, options.clientSecret);
}

util.inherits(WechatStrategy, OAuth2Strategy);

WechatStrategy.prototype.authenticate = function (req, options) {
    options = options || {};

    var self = this;

    if (req.query && req.query.error) {
        if (req.query.error == 'access_denied') {
            return this.fail({
                message: req.query.error_description
            });
        } else {
            return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
        }
    }

    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
            callbackURL = url.resolve(utils.originalURL(req, {
                proxy: this._trustProxy
            }), callbackURL);
        }
    }

    var scope = options.scope || this._scope;

    if (req.query && req.query.code) {
        var code = req.query.code;

        self._wechatOAuth.getAccessToken(code, function (err, result) {
            if (err) {
                return self.error(self._createOAuthError('Failed to obtain access token', err));
            }

            var params = result.data;
            self._params = params;

            var accessToken = params.access_token;
            var refreshToken = params.refresh_token;

            self._loadUserProfile(accessToken, function (err, profile) {
                if (err) {
                    return self.error(err);
                }

                function verified(err, user, info) {
                    if (err) {
                        return self.error(err);
                    }
                    if (!user) {
                        return self.fail(info);
                    }
                    self.success(user, info);
                }

                try {
                    if (self._passReqToCallback) {
                        var arity = self._verify.length;
                        if (arity == 6) {
                            self._verify(req, accessToken, refreshToken, params, profile, verified);
                        } else { // arity == 5
                            self._verify(req, accessToken, refreshToken, profile, verified);
                        }
                    } else {
                        var arity = self._verify.length;
                        if (arity == 5) {
                            self._verify(accessToken, refreshToken, params, profile, verified);
                        } else { // arity == 4
                            self._verify(accessToken, refreshToken, profile, verified);
                        }
                    }
                } catch (ex) {
                    return self.error(ex);
                }
            });
        });
    } else {
        var location = self._wechatOAuth.getAuthorizeURL(callbackURL, uid(24), scope);
        self.redirect(location);
    }
};

WechatStrategy.prototype.userProfile = function (accessToken, done) {
    var self = this;
    var data = self._params;

    var scope = options.scope || self._scope;
    if (scope === 'snsapi_userinfo') {
        var params = {
            openid: data.openid,
            access_token: accessToken,
            lang: 'zh_CN'
        };

        self._request('GET', 'https://api.weixin.qq.com/sns/userinfo', {}, params, accessToken, function (err, body, res) {
            if (err) {
                return done(new InternalOAuthError('Failed to fetch user profile', err));
            }

            try {
                var json = JSON.parse(body);
                var profile = {
                    provider: self.name
                };
                profile.id = json.unionid ? json.unionid : json.openid;
                profile.displayName = json.nickname;
                profile.openid = json.openid;
                profile.unionid = json.unionid;
                profile.photos = [{
                    value: json.headimgurl
            }]

                profile._raw = body;
                profile._json = json;

                done(null, profile);
            } catch (err) {
                done(new InternalOAuthError('Failed to fetch user profile', err));
            }
        });
    } else {
        done(null, {
            provider: self.name,
            id: data.unionid ? data.unionid : data.openid,
            openid: data.openid,
            unionid: data.unionid
        });
    }
};

/**
 * Expose `WechatStrategy`.
 */
module.exports = WechatStrategy;