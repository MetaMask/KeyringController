const getRandomValuesPoly = require('polyfill-crypto.getrandomvalues')

//
// polyfills
//

// overwrite node's promise with the stricter Bluebird promise
global.Promise = require('bluebird')

// dom
require('jsdom-global')()

// localStorage
window.localStorage = {}

// crypto.getRandomValues
if (!window.crypto) {
  window.crypto = {}
}

if (!window.crypto.getRandomValues) {
  window.crypto.getRandomValues = getRandomValuesPoly
}
