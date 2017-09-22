const ObservableStore = require('obs-store')
const clone = require('clone')
const ConfigManager = require('./config-manager')
const firstTimeState = require('./first-time-state')

module.exports = function () {
  const store = new ObservableStore(clone(firstTimeState))
  return new ConfigManager({ store })
}
