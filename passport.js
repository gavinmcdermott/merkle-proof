'use strict'

import crypto from 'crypto'
import _ from 'lodash'
import r from 'ramda'
// WARNING FOR LATER: I removed the call to .json in this package to use it in the browser
import elliptic from 'elliptic'
// WARNING FOR LATER: I removed the call to .json in this package to use it in the browser
import defaultData from './data'

// make sure we have personal data
if (!defaultData) {
  throw new Error('Expected data from a "personalInfo.js" file')
}
const defaultAttributes = ['firstName', 'address', 'socialSecurity']

// helper to hash values
const hashVals = (dataA, dataB) => {
  if (!dataB) {
    return crypto.createHmac('sha256', 'secret').update(dataA.toString()).digest('hex')
  }
  return crypto.createHmac('sha256', 'secret').update(dataA.toString()).update(dataB.toString()).digest('hex')
}

let initialized = false

let rawData = null
let parsedData = null

let merkleBase = null
let merkleRoot = null
let merkleTree = null

let keys = null
let signedRoot = null


const initKeys = () => {
  // Create and initialize EC context (better do it once and reuse it)
  if (keys) {
    return keys
  }
  let ec = new elliptic.ec('secp256k1')
  return ec.genKeyPair()
}

// parse an object of data - very naive for POC
let parseObject = (data) => {
  let handleAtomicData = (data, key) => {
    let strVal = data.toString()
    let hash = hashVals(strVal)
    let result = { hash, data }
    return result
  }

  let walkObject = (object) => {
    return _.transform(object, (result, data, objKey) => {
      if (_.isString(data) || _.isNumber(data)) {
        result[objKey] = handleAtomicData(data, objKey)
        return
      }
      if (_.isObject(data)) {
        return walkObject(data)
      }
    }, {})
  }
  return walkObject(data)
}

// transform the parsed data for merkle tree construction
let transformParsedObject = (data) => {
  return _.map(data, (val, key) => {
    return val.hash
  })
}


// Build hash levels of the merkle tree
let buildPairsFromLevel = (data) => {
  let hashes = Object.assign([], data)
  let results = []

  while (hashes.length > 1) {
    let hashPair = r.takeLast(2, hashes)
    let resultingHash = hashVals(hashPair[0], hashPair[1])
    // push values into the front!
    results.unshift(resultingHash)
    // trim down the hashes and data
    hashes = Object.assign([], r.dropLast(2, hashes))
  }

  // handle a last straggler
  if (hashes.length) {
    // push values into the front!
    results.unshift(_.first(hashes))
  }

  return results
}

// Build the tree
let buildTree = (data) => {
  // load in all hashes from the root level
  let result = [data]

  while (data.length > 1) {
    let nextPairs = buildPairsFromLevel(data)
    // push values into the front!
    result.unshift(nextPairs)
    data = nextPairs
  }

  return result
}


// Build a sharable package
let buildPackage = (attributes, merkleTree, personalData) => {
  let result = {
    attributes: {},
    merkleTree
  }
  let treeBase = _.flatten(merkleTree[merkleTree.length - 1])

  _.forEach(attributes, (attr, key) => {
    if (!_.has(personalData, attr)) {
      throw new Error('Property ', attr, ' does not exist')
    }
    let data = personalData[attr]

    if (_.indexOf(treeBase, data.hash) < 0) {
      throw new Error('Attribute hash missing from tree base')
    }
    result.attributes[attr] = {
      data: data.data,
      hash: data.hash,
      // valid: true
    }
  })

  return result
}


// API for the passport module
module.exports = {

  init: (data = defaultData) => {
    rawData = data

    try {
      parsedData = parseObject(data)
      merkleBase = transformParsedObject(parsedData)
      merkleTree = buildTree(merkleBase)
      merkleRoot = _.first(_.first(merkleTree))
      // obviously this leaves the priv key hanging out
      keys = initKeys()
    } catch (err) {
      throw err
    }
    initialized = true

    return {
      attributes: parsedData,
      raw: rawData,
      merkleTree
    }
  },

  sign: (data) => {
    return keys.sign(data)
  },

  verify: (data, signature) => {
    return keys.verify(data, signature)
  },

  build: (attributes = defaultAttributes) => {
    if (!initialized) {
      throw new Error('you must init the passport object!')
    }
    if (!_.isArray(attributes)) {
      throw new Error('expected an array')
    }
    return buildPackage(attributes, merkleTree, parsedData)
  }
}




// module.exports.init()
// let sig = module.exports.sign('ssdfd')
// console.log(sig)
// console.log(module.exports.verify('ssdfd', sig))
