// disallow promises from swallowing errors
enableFailureOnUnhandledPromiseRejection()

// logging util
const log = require('loglevel')

log.setDefaultLevel(5)

//
// polyfills
//

// dom
require('jsdom-global')()

// localStorage
window.localStorage = {}

// crypto.getRandomValues
if (!window.crypto) {
  window.crypto = {}
}
if (!window.crypto.getRandomValues) {
  /* eslint-disable-next-line */
  window.crypto.getRandomValues = require('polyfill-crypto.getrandomvalues')
}

function enableFailureOnUnhandledPromiseRejection (...args) {
  // overwrite node's promise with the stricter Bluebird promise
  global.Promise = require('bluebird') /* eslint-disable-line */

  // modified from https://github.com/mochajs/mocha/issues/1926#issuecomment-180842722

  // rethrow unhandledRejections
  if (typeof process !== 'undefined') {
    process.on('unhandledRejection', function (reason) {
      throw reason
    })
  } else if (typeof window !== 'undefined') {
    // 2016-02-01: No browsers support this natively, however bluebird, when.js,
    // and probably other libraries do.
    if (typeof window.addEventListener === 'function') {
      window.addEventListener('unhandledrejection', function (evt) {
        throw evt.detail.reason
      })
    } else {
      const oldOHR = window.onunhandledrejection
      window.onunhandledrejection = function (evt) {
        if (typeof oldOHR === 'function') {
          oldOHR.apply(this, args)
        }
        throw evt.detail.reason
      }
    }
  } else if (typeof console !== 'undefined' &&
      typeof (console.error || console.log) === 'function') {
    (console.error || console.log)('Unhandled rejections will be ignored!')
  }
}
