# @tamequest/account

### WARNING: You should not be storing private keys for wallets that hold large monetary values. Browser storage is inherently less secure than other methods. This library is intended mainly for burner/hot wallets.

# Introduction

This library is inteded to help with storing private keys in web applications that use the Algorand blockchain but prefer to simplify the signing process to button presses instead of the usual wallet connect method.

This approach should be used only with accounts generated for the sole purpose of usage inside your application.

It mainly implements [@webcrypto/storage](https://github.com/willgm/web-crypto-storage) together with [algosdk](https://algorand.github.io/js-algorand-sdk/) for managing accounts. It purposely only supports storing one wallet.

Rekey/multisig not supported.

## Example usage

### Create account

```
async (
    dispatch: (type: string, payload?: any) => void,
    password: string,
    account: algosdk.Account
  ) => {
    if (!(await isPasswordSet())) {
      await setPassword(password)
      if (await verifyPassword(password)) {
        await signIn(dispatch, await addAccount(account))
      }
    }
  }
```
