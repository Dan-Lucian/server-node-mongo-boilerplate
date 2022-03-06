const mongoose = require('mongoose');

const schemaUser = mongoose.Schema({
  username: {
    type: String,
    minLength: 3,
    required: true,
  },
  name: String,
  passwordHash: {
    type: String,
    required: true,
  },
  blogs: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Blog' }],
});

schemaUser.set('toJSON', {
  virtuals: true,
  versionKey: false,
  transform: (document, objectReturned) => {
    delete objectReturned._id;
    delete objectReturned.passwordHash;
  },
});

const User = mongoose.model('User', schemaUser);

module.exports = User;
