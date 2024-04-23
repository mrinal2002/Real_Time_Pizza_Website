const LocalStrategy = require('passport-local').Strategy; // Importing LocalStrategy from passport-local module
const User = require('../models/user'); // Importing User model
const bcrypt = require('bcrypt'); // Importing bcrypt for password hashing

function init(passport) {
    passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
        // Login authentication process
        // Check if email exists in the database
        const user = await User.findOne({ email: email });
        if (!user) {
            // If no user found with the provided email
            return done(null, false, { message: 'No user with this email' });
        }

        // Compare the provided password with the hashed password stored in the database
        bcrypt.compare(password, user.password).then(match => {
            if (match) {
                // If password matches
                return done(null, user, { message: 'Logged in successfully' });
            }
            // If password doesn't match
            return done(null, false, { message: 'Wrong username or password' });
        }).catch(err => {
            // Error handling for bcrypt comparison
            return done(null, false, { message: 'Something went wrong' });
        });
    }));

    // Serialize user object to store in session
    passport.serializeUser((user, done) => {
        done(null, user._id); // Storing user's MongoDB _id in the session
    });

    // Deserialize user object from session
    passport.deserializeUser((id, done) => {
        User.findById(id, (err, user) => {
            done(err, user); // Retrieving user object based on _id from the session
        });
    });
}

module.exports = init; // Exporting the initialization function for passport
