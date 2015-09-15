var secretbox = require('./01-secretbox');
var scalarmult = require('./02-scalarmult');
var box = require('./03-box');
var sign = require('./04-sign');

// print process.argv
process.argv.forEach(function (val, index, array) {
  console.log(index + ': ' + val);
});

if (process.argv[2]) {
  require('./' + process.argv[2])();
} else {
  secretbox();
  scalarmult();
  box();
  sign();
}
