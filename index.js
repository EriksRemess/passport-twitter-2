import { Strategy as PassportStrategy } from 'passport';
import crypto from 'crypto';

const generateRandomString = (symbols) => {
  const keys = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let text = '';
  do {
    text += keys[Math.floor(Math.random() * keys.length)];
    symbols -= 1;
  } while (symbols);
  return text;
};

export default class Strategy extends PassportStrategy {
  constructor(options, verify) {
    super();
    this.name = 'twitter';
    this._verify = verify;
    this._callbackURL = options.callbackURL;
    this._clientID = options.clientID;
    this._clientSecret = options.clientSecret;
    this.scope = [
      "tweet.read",
      "offline.access",
      "users.read",
    ];
  }
  async authenticate(req) {
    const verified = (error, user, info) => {
      if (error) return this.error(error);
      if (!user) return this.fail(info);
      return this.success(user, info);
    }
    if (req.query?.code && req.query?.state) {
      try {
        const { code, state } = req.query;
        const { code_verifier, state: session_state } = req.session;
        if (!code_verifier || !state || !session_state || !code) {
          return this.fail('You denied the app or your session expired!');
        }
        if (state !== session_state) {
          return this.fail('Stored tokens didn\'t match!');
        }
        let body = new URLSearchParams({
          code,
          code_verifier,
          redirect_uri: this._callbackURL,
          grant_type: 'authorization_code',
          client_id: this._clientID,
          client_secret: this._clientSecret,
        });
        let data = await fetch('https://api.twitter.com/2/oauth2/token', {
          method: 'POST',
          headers:  {
            Authorization: `Basic ${Buffer.from(`${encodeURIComponent(this._clientID)}:${encodeURIComponent(this._clientSecret)}`).toString('base64')}`,
          },
          body,
        }).then(res => res.json());
        const { access_token, refresh_token, expires_in } = data;
        if (!access_token) {
          return this.fail('No access token!');
        }
        let { data: profile } = await fetch('https://api.twitter.com/2/users/me', {
          headers: {
            Authorization: `Bearer ${access_token}`,
          }
        }).then(res => res.json());
        if (!profile) {
          return this.fail('No profile!');
        }
        return this._verify(access_token, refresh_token, profile, verified);
      } catch (error) {
        return this.error(error);
      }
    }
    if (req.query?.error) {
      return this.fail(req.query.error === "access_denied" ? "You denied the app!" : String(req.query.error));
    }
    let state = generateRandomString(32);
    let code_verifier = generateRandomString(128);
    let code_challenge = crypto
                                  .createHash('sha256')
                                  .update(code_verifier)
                                  .digest('base64')
                                  .replace(/\+/g, '-')
                                  .replace(/\//g, '_')
                                  .replace(/\=/g, '');
    req.session.code_verifier = code_verifier;
    req.session.code_challenge = code_challenge;
    req.session.state = state;
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this._clientID,
      redirect_uri: this._callbackURL,
      state,
      code_challenge,
      code_challenge_method: 'S256',
      scope: 'tweet.read offline.access users.read',
    }).toString();
    return this.redirect(`https://twitter.com/i/oauth2/authorize?${params}`);
  }
}

export { Strategy };
