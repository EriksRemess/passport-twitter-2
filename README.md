# Passport-Twitter-2

[Passport](http://passportjs.org/) strategy for authenticating with Twitter API v2

## Install

    $ npm install passport-twitter-2

## Usage

#### Configure Strategy
    import { Strategy as TwitterStrategy } from 'passport-twitter-2';
    passport.use(new TwitterStrategy({
        clientID: TWITTER_CLIENT_ID,
        appKey: TWITTER_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/twitter/callback"
      },
      function(accessToken, profile, done) {
        User.findOrCreate({ twitter: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'twitter'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/twitter',
      passport.authenticate('twitter'));

    app.get('/auth/twitter/callback',
      passport.authenticate('twitter', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Notes
Requires Node 18+, as the module uses Node's built-in Fetch.

## Credits

  - [Ēriks Remess](http://github.com/EriksRemess)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2022 Ēriks Remess