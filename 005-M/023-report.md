jonatascm

medium

# Not protected against signature malleability

## Summary

There are two issues related to signature malleability: 
1. The function `_validateSigner` is not using the correctly EIP-712
2. OpenZeppelin has a vulnerability in versions lower than 4.7.3, which an attacker can exploit. This project uses vulnerable version 4.3.2.

## Vulnerability Detail

All of the conditions from the advisory are satisfied: the signature comes in a single `bytes` argument, `ECDSA.recover()` is used, and the signatures themselves are used for replay protection checks [https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h)

Either a malicious user, in the case of `isInPrivateKeeperMode == false`, or a malicious keeper can bypass `_validateSigner`  either creating a new signature due to version of OZ or reusing a signature due to not correctly implementing of EIP-712, opening a queued trade with a different price or closing a valid queued trade through `resolveQueuedTrades` or changing priceAtExpiry while unlocking options through `unlockOptions`

## Impact

Some users could have their trade affected or the malicious user can win all his options by changing the priceAtExpiry

## Code Snippet

[[BufferRouter.sol#L260-L271](https://github.com/bufferfinance/Buffer-Protocol-v2/blob/83d85d9b18f1a4d09c728adaa0dde4c37406dfed/contracts/core/BufferRouter.sol#L260-L271)](https://github.com/bufferfinance/Buffer-Protocol-v2/blob/83d85d9b18f1a4d09c728adaa0dde4c37406dfed/contracts/core/BufferRouter.sol#L260-L271)

```solidity
function _validateSigner(
  uint256 timestamp,
  address asset,
  uint256 price,
  bytes memory signature
) internal view returns (bool) {
  bytes32 digest = ECDSA.toEthSignedMessageHash(
      keccak256(abi.encodePacked(timestamp, asset, price))
  );
  address recoveredSigner = ECDSA.recover(digest, signature);
  return recoveredSigner == publisher;
}
```

## Tool used

Manual Review

## Recommendation

1. Upgrade OZ version to 4.73 or 4.8.0.
2. Fix EIP-712 implementation by adding a nonce