const ethUtil = require('ethereumjs-util')
const rlp = require('rlp')
const Buffer = require('safe-buffer').Buffer

var Account = module.exports = function (data) {
    // Define Properties
    var fields = [{
        name: 'nonce',
        default: Buffer.alloc(0)
    }, {
        name: 'balance',
        default: Buffer.alloc(0)
    }, {
        name: 'identityRoot',
        length: 32,
        default: ethUtil.SHA3_RLP
    }, {
        name: 'stateRoot',
        length: 32,
        default: ethUtil.SHA3_RLP
    }, {
        name: 'codeHash',
        length: 32,
        default: ethUtil.SHA3_NULL
    }, {
        name: 'verificationContract',
        length: 32,
        default: 0
    }]

    ethUtil.defineProperties(this, fields, data)
}

Account.prototype.serialize = function () {
    return rlp.encode(this.raw)
}

Account.prototype.isContract = function () {
    return this.codeHash.toString('hex') !== ethUtil.SHA3_NULL_S
}

Account.prototype.hasVerificationContract = function () {
    return this.verificationContract.toString('hex') !== ethUtil.SHA3_NULL_S
}

Account.prototype.getCode = function (state, cb) {
    if (!this.isContract()) {
        cb(null, Buffer.alloc(0))
        return
    }

    state.getRaw(this.codeHash, cb)
}

Account.prototype.setCode = function (trie, code, cb) {
    var self = this

    this.codeHash = ethUtil.sha3(code)

    if (this.codeHash.toString('hex') === ethUtil.SHA3_NULL_S) {
        cb(null, Buffer.alloc(0))
        return
    }

    trie.putRaw(this.codeHash, code, function (err) {
        cb(err, self.codeHash)
    })
}

Account.prototype.getStorage = function (trie, key, cb) {
    var t = trie.copy()
    t.root = this.stateRoot
    t.get(key, cb)
}

Account.prototype.setCode = function (trie, code, cb) {
    var self = this

    this.codeHash = ethUtil.sha3(code)

    if (this.codeHash.toString('hex') === ethUtil.SHA3_NULL_S) {
        cb(null, Buffer.alloc(0))
        return
    }

    trie.putRaw(this.codeHash, code, function (err) {
        cb(err, self.codeHash)
    })
}

Account.prototype.getStorage = function (trie, key, cb) {
    var t = trie.copy()
    t.root = this.stateRoot
    t.get(key, cb)
}

Account.prototype.setStorage = function (trie, key, val, cb) {
    var self = this
    var t = trie.copy()
    t.root = self.stateRoot
    t.put(key, val, function (err) {
        if (err) return cb()
        self.stateRoot = t.root
        cb()
    })
}

Account.prototype.getIdentity = function (trie, key, cb) {
    var t = trie.copy()
    t.root = this.identityRoot
    t.get(key, cb)
}

Account.prototype.setIdentity = function (trie, key, val, cb) {
    var self = this
    var t = trie.copy()
    t.root = self.identityRoot
    t.put(key, val, function (err) {
        if (err) return cb()
        self.identityRoot = t.root
        cb()
    })
}


Account.prototype.getVerificationContract = function (state, cb) {
    if (!this.hasVerificationContract()) {
        cb(null, Buffer.alloc(0))
        return
    }

    state.getRaw(this.verificationContract, cb)
}

Account.prototype.setVerificationContract = function (trie, code, cb) {
    var self = this

    this.verificationContract = ethUtil.sha3(code)

    if (this.verificationContract.toString('hex') === ethUtil.SHA3_NULL_S) {
        cb(null, Buffer.alloc(0))
        return
    }

    trie.putRaw(this.verificationContract, code, function (err) {
        cb(err, self.verificationContract)
    })
}

Account.prototype.isEmpty = function () {
    return this.balance.toString('hex') === '' &&
        this.nonce.toString('hex') === '' &&
        this.stateRoot.toString('hex') === ethUtil.SHA3_RLP_S &&
        this.codeHash.toString('hex') === ethUtil.SHA3_NULL_S
}
