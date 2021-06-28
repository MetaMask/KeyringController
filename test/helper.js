//
// polyfills
//

// overwrite node's promise with the stricter Bluebird promise
global.Promise = require('bluebird')
