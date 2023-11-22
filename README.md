# @tamequest/account

### WARNING: You should not be storing private keys for wallets that hold large monetary values. Browser storage is inherently less secure than other methods. This library is intended mainly for burner/hot wallets.

# Introduction

This library is inteded to help with storing private keys in web applications that use the Algorand blockchain but prefer to simplify the signing process to button presses instead of the usual wallet connect method.

This approach should be used only with accounts generated for the sole purpose of usage inside your application.

It mainly implements [@webcrypto/storage](https://github.com/willgm/web-crypto-storage) together with [algosdk](https://algorand.github.io/js-algorand-sdk/) for managing accounts. It purposely only supports storing one wallet.

Rekey/multisig not supported.

# Installation

`yarn add @tamequest/account`

or

`npm i @tamequest/account`

# Example usage

### Imports

```
import {
  addAccount,
  createBackup,
  getAddress,
  isPasswordSet,
  lock,
  setPassword,
  signTransactions,
  verifyPassword
} from '@tamequest/account'
```

### Add account & password hash to storage

```
async function addAccount(
  password: string,
  account: algosdk.Account
): {
  if (!(await isPasswordSet())) {
    await setPassword(password)
    if (await verifyPassword(password)) {
      const accountAddress = await addAccount(account)
      if (accountAddress) {
        // ...perform sign in
      }
    }
  }
}
```

### Verify user password on sign in

```
async function signIn(
  password: string
): {
  if (await verifyPassword(password)) {
    const accountAddress = await getAddress()
    if (accountAddress) {
        // ...perform sign in
    }
  } else {
    // ...inform user password is invalid
  }
}
```

### Sign out

```
lock()
```

### Create backup

```
// prompt download of below returned text to a file
await createBackup(password)
```

### Sign transactions

```
// transactions: algosdk.Transaction[]
await signTransactions(transactions)
```

# Disclaimer

The code is provided as-is, with no guarantees of correctness or security.
