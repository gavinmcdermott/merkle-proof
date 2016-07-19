'use strict'

import Passport from './passport'
import $ from 'jquery'
import _ from 'lodash'

let passportInstance
let sharedPackage
let signedRoot
let merkleRoot

let updateSharedPackage = (data) => {
  sharedPackage = data
  $('#shared-data').text(JSON.stringify(sharedPackage.attributes, undefined, 2))
  $('#merkle-tree').text(JSON.stringify(sharedPackage.merkleTree, undefined, 2))
}

let showErr = (err) => {
  $('#warning').toggleClass('hidden')
  setTimeout(() => {
    $('#warning').toggleClass('hidden')
  }, 2000)
}

let signRoot = (evt) => {
  evt.preventDefault()

  merkleRoot = _.first(_.first(passportInstance.merkleTree))
  signedRoot = Passport.sign(merkleRoot)
  $('#signature').text(JSON.stringify(signedRoot, undefined, 2))
  $('#merkle-root').text(JSON.stringify(merkleRoot, undefined, 2))

  $('#signed-data').removeClass('hidden')
}

let verify = (evt) => {
  evt.preventDefault()
  $('#verified-data').removeClass('hidden')
  let isVerified = Passport.verify(merkleRoot, signedRoot)
  $('#verification-data').text(JSON.stringify({ isVerified: isVerified }, undefined, 2))

  // console.log(verified)
}

// let initWithNewAttributes = (evt) => {
//   evt.preventDefault()
//   let vals = $('#input').val().split(',')
//   let attributes = _.map(vals, _.trim)
//   let newPkg
//   try {
//     newPkg = Passport.build(attributes)
//   } catch (err) {
//     showErr(err)
//   }
//   if (newPkg) {
//     updateSharedPackage(newPkg)
//   }
// }

let initApp = () => {
  passportInstance = Passport.init()
  sharedPackage = Passport.build()


  // Load the full guts package JSON
  $('#preload-data').text(JSON.stringify(passportInstance.raw, undefined, 2))

  // Load the shared package UI
  updateSharedPackage(sharedPackage)

  // event handlers
  $('#verify').on('click', verify)
  $('#sign').on('click', signRoot)
}

initApp()
