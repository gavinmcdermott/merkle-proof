'use strict'

import Passport from './passport'



window.Passport = Passport.api


Passport.init()

console.log(window.Passport)